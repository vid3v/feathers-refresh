import { randomUUID } from 'node:crypto'
import type {
  IssueRefreshTokenInput,
  RefreshTokenRecord,
  RefreshTokenStore,
  RotateRefreshTokenInput,
  RotateResult
} from './types'

const cloneRecord = (record: RefreshTokenRecord): RefreshTokenRecord => ({
  ...record,
  expires_at: new Date(record.expires_at),
  revoked_at: record.revoked_at ? new Date(record.revoked_at) : null,
  created_at: new Date(record.created_at),
  updated_at: new Date(record.updated_at)
})

/**
 * In-memory {@link RefreshTokenStore}, keyed by token hash. Useful for tests and
 * lightweight deployments. Records live in `records` so tests can tamper with
 * expiry and revocation state directly.
 */
export class MemoryRefreshTokenStore implements RefreshTokenStore {
  readonly records = new Map<string, RefreshTokenRecord>()

  async issue(input: IssueRefreshTokenInput): Promise<RefreshTokenRecord> {
    const now = new Date()
    const record: RefreshTokenRecord = {
      id: randomUUID(),
      family_id: input.family_id,
      user_id: input.user_id,
      token_hash: input.token_hash,
      expires_at: new Date(input.expires_at),
      user_agent: input.user_agent ?? null,
      ip_address: input.ip_address ?? null,
      revoked_at: null,
      replaced_by_id: null,
      created_at: now,
      updated_at: now
    }
    this.records.set(record.token_hash, record)
    return cloneRecord(record)
  }

  async rotate(input: RotateRefreshTokenInput): Promise<RotateResult> {
    const oldRow = this.records.get(input.oldTokenHash)

    if (!oldRow) {
      return { ok: false, reason: 'invalid' }
    }

    if (oldRow.revoked_at != null) {
      return { ok: false, reason: 'reused', familyId: oldRow.family_id, userId: oldRow.user_id }
    }

    if (oldRow.expires_at.getTime() <= Date.now()) {
      return { ok: false, reason: 'expired' }
    }

    const now = new Date()
    const newRow: RefreshTokenRecord = {
      id: randomUUID(),
      family_id: oldRow.family_id,
      user_id: input.user_id,
      token_hash: input.token_hash,
      expires_at: new Date(input.expires_at),
      user_agent: input.user_agent ?? null,
      ip_address: input.ip_address ?? null,
      revoked_at: null,
      replaced_by_id: null,
      created_at: now,
      updated_at: now
    }
    this.records.set(newRow.token_hash, newRow)

    oldRow.revoked_at = now
    oldRow.replaced_by_id = newRow.id
    oldRow.updated_at = now

    return { ok: true, record: cloneRecord(newRow), familyId: oldRow.family_id }
  }

  async revokeFamily(familyId: string, userId?: string): Promise<number> {
    let count = 0
    for (const record of this.records.values()) {
      if (record.family_id !== familyId || record.revoked_at != null) {
        continue
      }
      if (userId != null && record.user_id !== userId) {
        continue
      }
      record.revoked_at = new Date()
      record.updated_at = record.revoked_at
      count++
    }
    return count
  }

  async revokeAllForUser(userId: string): Promise<number> {
    let count = 0
    for (const record of this.records.values()) {
      if (record.user_id !== userId || record.revoked_at != null) {
        continue
      }
      record.revoked_at = new Date()
      record.updated_at = record.revoked_at
      count++
    }
    return count
  }

  async findActiveByUser(userId: string): Promise<RefreshTokenRecord[]> {
    const now = Date.now()
    return Array.from(this.records.values())
      .filter(
        (record) =>
          record.user_id === userId && record.revoked_at == null && record.expires_at.getTime() > now
      )
      .sort((a, b) => b.created_at.getTime() - a.created_at.getTime())
      .map(cloneRecord)
  }

  async findByTokenHash(tokenHash: string): Promise<RefreshTokenRecord | undefined> {
    const record = this.records.get(tokenHash)
    return record ? cloneRecord(record) : undefined
  }

  async findById(id: string): Promise<RefreshTokenRecord | undefined> {
    for (const record of this.records.values()) {
      if (record.id === id) {
        return cloneRecord(record)
      }
    }
    return undefined
  }

  async purgeExpired(olderThan: Date): Promise<number> {
    let count = 0
    for (const [hash, record] of this.records.entries()) {
      if (record.expires_at.getTime() < olderThan.getTime()) {
        this.records.delete(hash)
        count++
      }
    }
    return count
  }
}
