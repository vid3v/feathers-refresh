import { randomUUID } from 'node:crypto'
import type { Db } from 'mongodb'
import type {
  IssueRefreshTokenInput,
  RefreshTokenRecord,
  RefreshTokenStore,
  RotateRefreshTokenInput,
  RotateResult
} from 'feathers-authentication-refresh'

export interface MongoStoreOptions {
  /** Collection name. Defaults to `refresh_tokens`. */
  collectionName?: string
}

/**
 * On-disk shape. `_id` holds the record id (a client-generated UUID) and is
 * surfaced as `id` on {@link RefreshTokenRecord}. Field names use snake_case
 * to match the store contract.
 */
interface RefreshTokenDocument {
  _id: string
  family_id: string
  user_id: string
  token_hash: string
  expires_at: Date
  user_agent: string | null
  ip_address: string | null
  revoked_at: Date | null
  replaced_by_id: string | null
  created_at: Date
  updated_at: Date
}

const asDate = (value: Date | string): Date => (value instanceof Date ? value : new Date(value))

const toRecord = (doc: RefreshTokenDocument): RefreshTokenRecord => {
  const { _id, ...rest } = doc
  return {
    ...rest,
    id: _id,
    expires_at: asDate(doc.expires_at),
    revoked_at: doc.revoked_at == null ? null : asDate(doc.revoked_at),
    created_at: asDate(doc.created_at),
    updated_at: asDate(doc.updated_at)
  }
}

/**
 * MongoDB adapter for the {@link RefreshTokenStore} contract, built on the
 * official `mongodb` driver.
 *
 * Security properties:
 * - `token_hash` stores SHA-256(token), never the raw token (hashing happens in
 *   the core package — this store only ever sees hashes)
 * - rotation is atomic without transactions: the consumed row is claimed with a
 *   conditional `updateOne({ _id, revoked_at: null })`, so concurrent rotations
 *   of the same token are serialized and the loser is reported as a reuse
 * - works on standalone servers as well as replica sets (no multi-document
 *   transaction required)
 * - a token that has already been revoked and is presented again reports `reused`,
 *   triggering a whole-family revocation in the caller (OWASP refresh token rotation)
 */
export class MongoRefreshTokenStore implements RefreshTokenStore {
  constructor(
    private readonly db: Db,
    private readonly options: MongoStoreOptions = {}
  ) {}

  private get collection() {
    return this.db.collection<RefreshTokenDocument>(this.options.collectionName ?? 'refresh_tokens')
  }

  async issue(input: IssueRefreshTokenInput): Promise<RefreshTokenRecord> {
    const now = new Date()
    const doc: RefreshTokenDocument = {
      _id: randomUUID(),
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
    await this.collection.insertOne(doc)
    return toRecord(doc)
  }

  async rotate(input: RotateRefreshTokenInput): Promise<RotateResult> {
    const oldDoc = await this.collection.findOne({ token_hash: input.oldTokenHash })

    if (!oldDoc) {
      return { ok: false, reason: 'invalid' }
    }

    if (oldDoc.revoked_at != null) {
      return { ok: false, reason: 'reused', familyId: oldDoc.family_id, userId: oldDoc.user_id }
    }

    if (asDate(oldDoc.expires_at).getTime() <= Date.now()) {
      return { ok: false, reason: 'expired' }
    }

    const now = new Date()
    const newDoc: RefreshTokenDocument = {
      _id: randomUUID(),
      family_id: oldDoc.family_id,
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
    await this.collection.insertOne(newDoc)

    // Conditional update = the atomicity barrier. Concurrent rotations of the
    // same token race on this single document: the loser matches no row, sees
    // `revoked_at` set by the winner, and is treated as a reuse (the family
    // gets revoked by the caller).
    const updated = await this.collection.updateOne(
      { _id: oldDoc._id, revoked_at: null },
      { $set: { revoked_at: now, replaced_by_id: newDoc._id, updated_at: now } }
    )

    if (updated.matchedCount === 0) {
      return { ok: false, reason: 'reused', familyId: oldDoc.family_id, userId: oldDoc.user_id }
    }

    return { ok: true, record: toRecord(newDoc), familyId: oldDoc.family_id }
  }

  async revokeFamily(familyId: string, userId?: string): Promise<number> {
    const now = new Date()
    const result = await this.collection.updateMany(
      {
        family_id: familyId,
        revoked_at: null,
        ...(userId != null ? { user_id: userId } : {})
      },
      { $set: { revoked_at: now, updated_at: now } }
    )
    return result.modifiedCount
  }

  async revokeAllForUser(userId: string): Promise<number> {
    const now = new Date()
    const result = await this.collection.updateMany(
      { user_id: userId, revoked_at: null },
      { $set: { revoked_at: now, updated_at: now } }
    )
    return result.modifiedCount
  }

  async findActiveByUser(userId: string): Promise<RefreshTokenRecord[]> {
    const docs = await this.collection
      .find(
        { user_id: userId, revoked_at: null, expires_at: { $gt: new Date() } },
        // `token_hash` is excluded: session-management views never need it.
        { projection: { token_hash: 0 } }
      )
      .sort({ created_at: -1 })
      .toArray()
    return docs.map(toRecord)
  }

  async findByTokenHash(tokenHash: string): Promise<RefreshTokenRecord | undefined> {
    const doc = await this.collection.findOne({ token_hash: tokenHash })
    return doc ? toRecord(doc) : undefined
  }

  async findById(id: string): Promise<RefreshTokenRecord | undefined> {
    const doc = await this.collection.findOne({ _id: id })
    return doc ? toRecord(doc) : undefined
  }

  async purgeExpired(olderThan: Date): Promise<number> {
    const result = await this.collection.deleteMany({ expires_at: { $lt: olderThan } })
    return result.deletedCount
  }
}
