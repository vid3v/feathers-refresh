import type { Collection, Db } from 'mongodb'

export * from './store'

/**
 * Creates the indexes the store relies on, on `db.collection('refresh_tokens')`
 * (or the collection name given via `collectionName`).
 *
 * ```ts
 * import { MongoClient } from 'mongodb'
 * import { createRefreshTokensIndexes } from 'feathers-authentication-refresh-mongodb'
 *
 * const client = new MongoClient(process.env.MONGODB_URL)
 * await client.connect()
 * await createRefreshTokensIndexes(client.db())
 * ```
 *
 * No TTL index is created on purpose: expired tokens must be retained for the
 * audit/reuse-detection window and are removed by the core package's purge job
 * (`purgeExpired`).
 */
export const createRefreshTokensIndexes = async (
  db: Db,
  collectionName = 'refresh_tokens'
): Promise<void> => {
  const collection: Collection = db.collection(collectionName)
  await collection.createIndex({ token_hash: 1 }, { unique: true, name: 'token_hash_unique' })
  await collection.createIndex({ user_id: 1 }, { name: 'user_id' })
  await collection.createIndex({ family_id: 1 }, { name: 'family_id' })
  await collection.createIndex({ expires_at: 1 }, { name: 'expires_at' })
}

/** Drops the refresh tokens collection. */
export const dropRefreshTokensCollection = async (
  db: Db,
  collectionName = 'refresh_tokens'
): Promise<void> => {
  await db.dropCollection(collectionName)
}
