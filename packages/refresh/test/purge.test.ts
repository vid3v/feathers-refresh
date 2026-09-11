import assert from 'assert'
import type { Application } from '@feathersjs/feathers'

import { MemoryRefreshTokenStore, createPurgeJob, purgeJob } from '../src'
import type { PurgeJobHandle, RefreshTokenRecord } from '../src'
import { createApp, createTestUser, loginUser, AUTH_CONFIG } from './fixtures'

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

const issueRecord = async (store: MemoryRefreshTokenStore, overrides: Partial<RefreshTokenRecord> = {}) => {
  const record = await store.issue({
    user_id: 'u1',
    family_id: 'f1',
    token_hash: overrides.token_hash ?? `hash-${Math.random()}`,
    expires_at: new Date(Date.now() + 60_000)
  })
  if (overrides.expires_at || overrides.revoked_at !== undefined) {
    const row = store.records.get(record.token_hash)!
    row.expires_at = overrides.expires_at ?? row.expires_at
    row.revoked_at = overrides.revoked_at ?? null
  }
  return record
}

describe('expired-token purge job', () => {
  describe('createPurgeJob', () => {
    it('run() deletes expired tokens and returns the deleted count', async () => {
      const store = new MemoryRefreshTokenStore()
      const expired = await issueRecord(store, { expires_at: new Date(Date.now() - 60_000) })
      const active = await issueRecord(store)
      const job = createPurgeJob(store, { interval: '1h' })

      const deleted = await job.run()

      assert.strictEqual(deleted, 1)
      assert.ok(!store.records.has(expired.token_hash))
      assert.ok(store.records.has(active.token_hash))

      job.stop()
    })

    it('deletes expired rows regardless of revocation state (retention window governs audit history)', async () => {
      const store = new MemoryRefreshTokenStore()
      await issueRecord(store, {
        expires_at: new Date(Date.now() - 60_000),
        revoked_at: new Date(Date.now() - 30_000)
      })
      const job = createPurgeJob(store, { interval: '1h' })

      assert.strictEqual(await job.run(), 1)
      assert.strictEqual(store.records.size, 0)

      job.stop()
    })

    it('olderThan applies a retention window to the expiry date', async () => {
      const store = new MemoryRefreshTokenStore()
      const recent = await issueRecord(store, { expires_at: new Date(Date.now() - 5_000) })
      const ancient = await issueRecord(store, { expires_at: new Date(Date.now() - 120_000) })
      const job = createPurgeJob(store, { interval: '1h', olderThan: '1m' })

      const deleted = await job.run()

      assert.strictEqual(deleted, 1)
      assert.ok(store.records.has(recent.token_hash))
      assert.ok(!store.records.has(ancient.token_hash))

      job.stop()
    })

    it('rejects a non-positive interval', () => {
      assert.throws(() => createPurgeJob(new MemoryRefreshTokenStore(), { interval: '0s' }))
    })

    it('runs on a schedule until stopped', async function () {
      this.timeout(5000)
      const store = new MemoryRefreshTokenStore()
      let runs = 0
      const job = createPurgeJob(store, {
        interval: '1s',
        onError: () => {}
      })
      // Wrap purgeExpired to observe scheduled runs.
      const original = store.purgeExpired.bind(store)
      store.purgeExpired = async (olderThan: Date) => {
        runs++
        return original(olderThan)
      }

      assert.ok(job.isRunning())
      await sleep(2300)
      assert.ok(runs >= 2, `expected at least 2 scheduled runs, got ${runs}`)

      job.stop()
      const runsAtStop = runs
      assert.ok(!job.isRunning())
      await sleep(1200)
      assert.strictEqual(runs, runsAtStop, 'no runs after stop()')
    })

    it('runOnStart executes one pass immediately', async () => {
      const store = new MemoryRefreshTokenStore()
      await issueRecord(store, { expires_at: new Date(Date.now() - 60_000) })
      const job = createPurgeJob(store, { interval: '1h', runOnStart: true })

      await sleep(20)
      assert.strictEqual(store.records.size, 0)

      job.stop()
    })

    it('reports scheduled failures through onError instead of crashing', async function () {
      this.timeout(5000)
      const errors: Error[] = []
      const base = new MemoryRefreshTokenStore()
      const failingStore = Object.assign(base, {
        purgeExpired: async () => {
          throw new Error('store down')
        }
      })
      const job = createPurgeJob(failingStore, { interval: '1s', onError: (e) => errors.push(e) })

      await sleep(1200)
      // The schedule survived the failure.
      assert.ok(job.isRunning())
      job.stop()
      // One scheduled run happened and its error was reported.
      assert.strictEqual(errors.length, 1)
      assert.strictEqual(errors[0].message, 'store down')
      assert.ok(!job.isRunning())
    })
  })

  describe('purgeJob plugin', () => {
    it('resolves the store from the app and registers the handle', async () => {
      const { app, store } = createApp(new MemoryRefreshTokenStore())
      const expired = await issueRecord(store, { expires_at: new Date(Date.now() - 60_000) })

      app.configure(purgeJob({ interval: '1h' }))

      const job = app.get('refreshPurgeJob') as PurgeJobHandle
      assert.ok(job, 'refreshPurgeJob handle registered')
      assert.strictEqual(await job.run(), 1)
      assert.ok(!store.records.has(expired.token_hash))

      job.stop()
    })

    it('fails when no store is configured', () => {
      const app = {
        get: () => undefined,
        set: () => {},
        configure: (fn: (a: unknown) => void) => fn(app)
      } as unknown as Application
      assert.throws(() => app.configure(purgeJob({})), /No refresh token store configured/)
    })

    it('refresh({ purge }) starts the job in one step', async () => {
      const created = createApp(new MemoryRefreshTokenStore(), {
        ...AUTH_CONFIG,
        refresh: { ...AUTH_CONFIG.refresh }
      })
      const { app, store } = created
      // Reconfigure with the purge option.
      const { refresh } = await import('../src')
      app.configure(
        refresh({
          store,
          purge: { interval: '1h', olderThan: '30d' }
        })
      )
      const job = app.get('refreshPurgeJob') as PurgeJobHandle
      assert.ok(job, 'purge job started by refresh()')
      // The 30d retention window protects a recently expired token...
      await issueRecord(store, { token_hash: 'recent', expires_at: new Date(Date.now() - 120_000) })
      // ...but not one expired since longer than the window.
      await issueRecord(store, {
        token_hash: 'ancient',
        expires_at: new Date(Date.now() - 40 * 86_400_000)
      })
      assert.strictEqual(await job.run(), 1)
      assert.ok(store.records.has('recent'))
      assert.ok(!store.records.has('ancient'))

      job.stop()
    })
  })

  describe('end to end', () => {
    it('purges rotated-away tokens but keeps active sessions working', async () => {
      const { app, store } = createApp(new MemoryRefreshTokenStore())
      await createTestUser(app as never)
      const login = await loginUser(app as never)

      const job = createPurgeJob(store, { interval: '1h' })
      assert.strictEqual(await job.run(), 0)

      // Rotate — the old token becomes consumed/expired-for-good.
      const rotated = await app
        .service('authentication')
        .create({ strategy: 'refresh', refreshToken: login.refreshToken }, {})

      // Even with a retention window of 0 the active token survives...
      assert.strictEqual(await job.run(), 0)
      const active = await app
        .service('authentication')
        .create({ strategy: 'refresh', refreshToken: rotated.refreshToken }, {})
      assert.ok(active.accessToken)

      // ...and once it expires past the retention window it is deleted.
      const record = Array.from(store.records.values()).find((r) => r.token_hash !== login.refreshToken)
      assert.ok(record)
      store.records.get(record.token_hash)!.expires_at = new Date(Date.now() - 60_000)
      assert.strictEqual(await job.run(), 1)

      job.stop()
    })
  })
})
