import { randomUUID } from 'node:crypto'
import type { Knex } from 'knex'
import type {
  IssueRefreshTokenInput,
  RefreshTokenRecord,
  RefreshTokenStore,
  RotateRefreshTokenInput,
  RotateResult
} from 'feathers-authentication-refresh'

export interface KnexStoreOptions {
  /** Table name. Defaults to `refresh_tokens`. */
  tableName?: string
}

/** Dialects whose query builder supports `SELECT ... FOR UPDATE`. */
const FOR_UPDATE_CLIENTS = [
  'pg',
  'pg-native',
  'redshift',
  'mssql',
  'mysql',
  'mysql2',
  'oracledb',
  'cockroachdb'
]

const asDate = (value: Date | string): Date => (value instanceof Date ? value : new Date(value))

const toRecord = (row: Record<string, any>): RefreshTokenRecord => ({
  ...(row as RefreshTokenRecord),
  expires_at: asDate(row.expires_at),
  revoked_at: row.revoked_at == null ? null : asDate(row.revoked_at),
  created_at: asDate(row.created_at),
  updated_at: asDate(row.updated_at)
})

/**
 * SQL adapter for the {@link RefreshTokenStore} contract, built on Knex.
 * Tested with PostgreSQL and SQLite; works with any Knex-supported dialect.
 *
 * Security properties:
 * - `token_hash` stores SHA-256(token), never the raw token (hashing happens in the core
 *   package — this store only ever sees hashes)
 * - rotation is transactional, with a `SELECT ... FOR UPDATE` lock on the consumed row
 *   where the dialect supports it
 * - a token that has already been revoked and is presented again reports `reused`,
 *   triggering a whole-family revocation in the caller (OWASP refresh token rotation)
 */
export class KnexRefreshTokenStore implements RefreshTokenStore {
  constructor(
    private readonly knex: Knex,
    private readonly options: KnexStoreOptions = {}
  ) {}

  private get table(): string {
    return this.options.tableName ?? 'refresh_tokens'
  }

  async issue(input: IssueRefreshTokenInput): Promise<RefreshTokenRecord> {
    const now = new Date()
    const row = {
      id: randomUUID(),
      family_id: input.family_id,
      user_id: input.user_id,
      token_hash: input.token_hash,
      expires_at: input.expires_at,
      user_agent: input.user_agent ?? null,
      ip_address: input.ip_address ?? null,
      revoked_at: null,
      replaced_by_id: null,
      created_at: now,
      updated_at: now
    }
    await this.knex(this.table).insert(row)
    return toRecord(row)
  }

  async rotate(input: RotateRefreshTokenInput): Promise<RotateResult> {
    return this.knex.transaction(async (trx): Promise<RotateResult> => {
      // Locking the row serializes concurrent refreshes: the loser sees
      // revoked_at set and goes through reuse detection.
      let select = trx(this.table).where({ token_hash: input.oldTokenHash })
      if (FOR_UPDATE_CLIENTS.includes(this.knex.client.config.client as string)) {
        select = select.forUpdate()
      }
      const oldRow = await select.first()

      if (!oldRow) {
        return { ok: false, reason: 'invalid' }
      }

      if (oldRow.revoked_at != null) {
        return { ok: false, reason: 'reused', familyId: oldRow.family_id, userId: oldRow.user_id }
      }

      if (asDate(oldRow.expires_at).getTime() <= Date.now()) {
        return { ok: false, reason: 'expired' }
      }

      const now = new Date()
      const newRow = {
        id: randomUUID(),
        family_id: oldRow.family_id,
        user_id: input.user_id,
        token_hash: input.token_hash,
        expires_at: input.expires_at,
        user_agent: input.user_agent ?? null,
        ip_address: input.ip_address ?? null,
        revoked_at: null,
        replaced_by_id: null,
        created_at: now,
        updated_at: now
      }
      await trx(this.table).insert(newRow)

      // Cannot normally happen because of the FOR UPDATE lock. If it does, we
      // treat it as a reuse: the family gets revoked by the caller.
      const updated = await trx(this.table).where({ id: oldRow.id }).whereNull('revoked_at').update({
        revoked_at: trx.fn.now(),
        replaced_by_id: newRow.id,
        updated_at: trx.fn.now()
      })

      if (updated === 0) {
        return { ok: false, reason: 'reused', familyId: oldRow.family_id, userId: oldRow.user_id }
      }

      return { ok: true, record: toRecord(newRow), familyId: oldRow.family_id }
    })
  }

  async revokeFamily(familyId: string, userId?: string): Promise<number> {
    let query = this.knex(this.table)
      .where({ family_id: familyId })
      .whereNull('revoked_at')
      .update({ revoked_at: this.knex.fn.now(), updated_at: this.knex.fn.now() })

    if (userId != null) {
      query = query.where({ user_id: userId })
    }

    return query
  }

  async revokeAllForUser(userId: string): Promise<number> {
    return this.knex(this.table)
      .where({ user_id: userId })
      .whereNull('revoked_at')
      .update({ revoked_at: this.knex.fn.now(), updated_at: this.knex.fn.now() })
  }

  async findActiveByUser(userId: string): Promise<RefreshTokenRecord[]> {
    const rows = await this.knex(this.table)
      .select('id', 'family_id', 'user_id', 'user_agent', 'ip_address', 'created_at', 'expires_at')
      .where({ user_id: userId })
      .whereNull('revoked_at')
      .where('expires_at', '>', new Date())
      .orderBy('created_at', 'desc')
    return rows.map(toRecord) as unknown as RefreshTokenRecord[]
  }

  async findByTokenHash(tokenHash: string): Promise<RefreshTokenRecord | undefined> {
    const row = await this.knex(this.table).where({ token_hash: tokenHash }).first()
    return row ? toRecord(row) : undefined
  }

  async findById(id: string): Promise<RefreshTokenRecord | undefined> {
    const row = await this.knex(this.table).where({ id }).first()
    return row ? toRecord(row) : undefined
  }

  async purgeExpired(olderThan: Date): Promise<number> {
    return this.knex(this.table).where('expires_at', '<', olderThan).del()
  }
}
