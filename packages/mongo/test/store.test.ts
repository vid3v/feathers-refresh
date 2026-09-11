import assert from 'assert'
import { MongoClient } from 'mongodb'
import { MongoMemoryServer } from 'mongodb-memory-server'

import { hashToken } from 'feathers-authentication-refresh'
import { MongoRefreshTokenStore, createRefreshTokensIndexes, dropRefreshTokensCollection } from '../src'

describe('MongoRefreshTokenStore', () => {
  let mongoServer: MongoMemoryServer
  let client: MongoClient
  let store: MongoRefreshTokenStore

  const issueToken = (overrides: Record<string, unknown> = {}) =>
    store.issue({
      user_id: 'user-1',
      family_id: 'family-1',
      token_hash: hashToken(`token-${Math.random()}`),
      expires_at: new Date(Date.now() + 60 * 60 * 1000),
      user_agent: 'test-agent',
      ip_address: '127.0.0.1',
      ...overrides
    })

  before(async () => {
    mongoServer = await MongoMemoryServer.create()
    client = new MongoClient(mongoServer.getUri())
    await client.connect()
  })

  after(async () => {
    await client?.close()
    await mongoServer?.stop()
  })

  beforeEach(async () => {
    await createRefreshTokensIndexes(client.db())
    store = new MongoRefreshTokenStore(client.db())
  })

  afterEach(async () => {
    await dropRefreshTokensCollection(client.db())
  })

  it('issues and finds tokens by hash', async () => {
    const record = await issueToken()

    assert.ok(record.id)
    assert.strictEqual(record.user_id, 'user-1')
    assert.strictEqual(record.revoked_at, null)

    const found = await store.findByTokenHash(record.token_hash)
    assert.strictEqual(found?.id, record.id)
    assert.ok(found?.expires_at instanceof Date)

    const byId = await store.findById(record.id)
    assert.strictEqual(byId?.token_hash, record.token_hash)
    assert.strictEqual(await store.findById('missing'), undefined)
  })

  it('rotates a token atomically', async () => {
    const old = await issueToken()

    const result = await store.rotate({
      oldTokenHash: old.token_hash,
      token_hash: hashToken('replacement'),
      user_id: 'user-1',
      family_id: old.family_id,
      expires_at: new Date(Date.now() + 60 * 60 * 1000)
    })

    assert.ok(result.ok)
    const oldRow = await store.findByTokenHash(old.token_hash)
    assert.ok(oldRow?.revoked_at)
    assert.strictEqual(oldRow?.replaced_by_id, result.ok ? result.record.id : undefined)
  })

  it('reports reuse when a revoked token is rotated again', async () => {
    const old = await issueToken()

    await store.rotate({
      oldTokenHash: old.token_hash,
      token_hash: hashToken('replacement-1'),
      user_id: 'user-1',
      family_id: old.family_id,
      expires_at: new Date(Date.now() + 60 * 60 * 1000)
    })

    const result = await store.rotate({
      oldTokenHash: old.token_hash,
      token_hash: hashToken('replacement-2'),
      user_id: 'user-1',
      family_id: old.family_id,
      expires_at: new Date(Date.now() + 60 * 60 * 1000)
    })

    assert.deepStrictEqual(result, {
      ok: false,
      reason: 'reused',
      familyId: old.family_id,
      userId: 'user-1'
    })
  })

  it('serializes concurrent rotations of the same token', async () => {
    const old = await issueToken()

    const results = await Promise.all([
      store.rotate({
        oldTokenHash: old.token_hash,
        token_hash: hashToken('replacement-1'),
        user_id: 'user-1',
        family_id: old.family_id,
        expires_at: new Date(Date.now() + 60 * 60 * 1000)
      }),
      store.rotate({
        oldTokenHash: old.token_hash,
        token_hash: hashToken('replacement-2'),
        user_id: 'user-1',
        family_id: old.family_id,
        expires_at: new Date(Date.now() + 60 * 60 * 1000)
      })
    ])

    // Exactly one rotation succeeds; the loser is reported as a reuse.
    const successes = results.filter((r) => r.ok)
    const reuses = results.filter((r) => !r.ok && r.reason === 'reused')
    assert.strictEqual(successes.length, 1)
    assert.strictEqual(reuses.length, 1)
    if (!reuses[0].ok) {
      assert.strictEqual(reuses[0].familyId, old.family_id)
    }
  })

  it('reports expired tokens', async () => {
    const old = await issueToken({ expires_at: new Date(Date.now() - 1000) })

    const result = await store.rotate({
      oldTokenHash: old.token_hash,
      token_hash: hashToken('replacement'),
      user_id: 'user-1',
      family_id: old.family_id,
      expires_at: new Date(Date.now() + 60 * 60 * 1000)
    })

    assert.strictEqual(result.ok, false)
    assert.strictEqual((result as { reason: string }).reason, 'expired')
  })

  it('reports unknown tokens', async () => {
    const result = await store.rotate({
      oldTokenHash: hashToken('unknown'),
      token_hash: hashToken('replacement'),
      user_id: 'user-1',
      family_id: 'family-1',
      expires_at: new Date(Date.now() + 60 * 60 * 1000)
    })

    assert.strictEqual((result as { reason: string }).reason, 'invalid')
  })

  it('revokes a family and lists active tokens', async () => {
    const first = await issueToken({ family_id: 'family-1' })
    const second = await issueToken({ family_id: 'family-2' })

    assert.strictEqual(await store.findActiveByUser('user-1').then((r) => r.length), 2)

    await store.revokeFamily('family-1')

    const active = await store.findActiveByUser('user-1')
    assert.strictEqual(active.length, 1)
    assert.strictEqual(active[0].id, second.id)

    const revoked = await store.findByTokenHash(first.token_hash)
    assert.ok(revoked?.revoked_at)
  })

  it('lists active tokens with session-management fields', async () => {
    await issueToken({ family_id: 'family-1' })

    const active = await store.findActiveByUser('user-1')
    assert.strictEqual(active.length, 1)
    // `updated_at` backs the `last_used_at` field of the session service view
    assert.ok(active[0].updated_at instanceof Date)
  })

  it('revokes all tokens of a user', async () => {
    await issueToken({ user_id: 'user-1' })
    await issueToken({ user_id: 'user-2' })

    assert.strictEqual(await store.revokeAllForUser('user-1'), 1)
    assert.strictEqual(await store.findActiveByUser('user-1').then((r) => r.length), 0)
    assert.strictEqual(await store.findActiveByUser('user-2').then((r) => r.length), 1)
  })

  it('purges expired tokens', async () => {
    const old = await issueToken({ expires_at: new Date(Date.now() - 5000) })
    await issueToken()

    assert.strictEqual(await store.purgeExpired(new Date(Date.now() - 1000)), 1)
    assert.strictEqual(await store.findByTokenHash(old.token_hash), undefined)
  })
})
