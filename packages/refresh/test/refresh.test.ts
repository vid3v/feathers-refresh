import assert from 'assert'
import jsonwebtoken from 'jsonwebtoken'
import { NotAuthenticated } from '@feathersjs/errors'
import type { Application } from '@feathersjs/feathers'

import { MemoryRefreshTokenStore, hashToken } from '../src'
import type { RefreshConfig } from '../src'
import type { RefreshTokenRecord } from '../src'
import { createApp, createTestUser, loginUser, AUTH_CONFIG } from './fixtures'

describe('feathers-authentication-refresh', () => {
  type TestApp = { app: Application; store: MemoryRefreshTokenStore }

  let app: Application
  let store: MemoryRefreshTokenStore
  let user: Record<string, any>
  let login: Record<string, any>

  const setup = async (authConfig: typeof AUTH_CONFIG & { refresh: RefreshConfig } = AUTH_CONFIG) => {
    const created: TestApp = createApp(new MemoryRefreshTokenStore(), authConfig)
    app = created.app
    store = created.store
    user = await createTestUser(app as never)
    login = await loginUser(app as never)
  }

  const refreshCall = (refreshToken: string) =>
    app.service('authentication').create({ strategy: 'refresh', refreshToken }, {}) as Promise<
      Record<string, any>
    >

  const expectNotAuthenticated = async (promise: Promise<unknown>, message?: string) => {
    try {
      await promise
      assert.fail('Expected the call to fail')
    } catch (error) {
      assert.ok(error instanceof NotAuthenticated, `Expected NotAuthenticated, got ${error}`)
      if (message) {
        assert.strictEqual((error as Error).message, message)
      }
    }
  }

  describe('login', () => {
    beforeEach(() => setup())

    it('issues an access token and a refresh token', async () => {
      assert.ok(login.accessToken)
      assert.ok(login.refreshToken)
    })

    it('adds the session id to the access token', async () => {
      const payload = jsonwebtoken.decode(login.accessToken) as Record<string, any>
      assert.strictEqual(payload.sub, String(user.id))
      assert.strictEqual(typeof payload.sid, 'string')
      assert.strictEqual(payload.typ, undefined)
    })

    it('signs the refresh token with a dedicated secret and typ claim', async () => {
      const payload = jsonwebtoken.decode(login.refreshToken) as Record<string, any>
      const accessPayload = jsonwebtoken.decode(login.accessToken) as Record<string, any>
      assert.strictEqual(payload.typ, 'refresh')
      assert.strictEqual(payload.sid, accessPayload.sid)
      assert.strictEqual(payload.sub, String(user.id))
      // Signed with the dedicated refresh secret, not the access token secret
      assert.throws(() => jsonwebtoken.verify(login.refreshToken, AUTH_CONFIG.secret))
      jsonwebtoken.verify(login.refreshToken, AUTH_CONFIG.refresh.secret)
    })

    it('stores only the hash of the refresh token', async () => {
      const record = await store.findByTokenHash(hashToken(login.refreshToken))
      assert.ok(record)
      assert.strictEqual(record?.user_id, String(user.id))
      assert.strictEqual(record?.revoked_at, null)
      assert.ok(!JSON.stringify(Array.from(store.records.values())).includes(login.refreshToken))

      const byId = await store.findById(record!.id)
      assert.strictEqual(byId?.token_hash, hashToken(login.refreshToken))
      assert.strictEqual(await store.findById('missing'), undefined)
    })
  })

  describe('refresh rotation', () => {
    beforeEach(() => setup())

    it('issues a new token pair and revokes the old refresh token', async () => {
      const rotated = await refreshCall(login.refreshToken)

      assert.ok(rotated.accessToken)
      assert.notStrictEqual(rotated.refreshToken, login.refreshToken)

      const payload = jsonwebtoken.decode(rotated.refreshToken) as Record<string, any>
      const oldPayload = jsonwebtoken.decode(login.refreshToken) as Record<string, any>
      // Rotation stays within the same session family
      assert.strictEqual(payload.sid, oldPayload.sid)

      const oldRecord = await store.findByTokenHash(hashToken(login.refreshToken))
      assert.ok(oldRecord?.revoked_at)
      assert.strictEqual(
        oldRecord?.replaced_by_id,
        (await store.findByTokenHash(hashToken(rotated.refreshToken)))?.id
      )
    })

    it('rejects replaying a rotated refresh token and revokes the whole family', async () => {
      const rotated = await refreshCall(login.refreshToken)

      await expectNotAuthenticated(
        refreshCall(login.refreshToken),
        'Refresh token reuse detected, the session has been revoked'
      )

      // Every token of the family was revoked — even the newest one
      const newest = await store.findByTokenHash(hashToken(rotated.refreshToken))
      assert.ok(newest?.revoked_at)
      await expectNotAuthenticated(refreshCall(rotated.refreshToken))
    })

    it('rejects unknown refresh tokens', async () => {
      await expectNotAuthenticated(refreshCall('not-a-token'), 'Invalid refresh token')
    })

    it('rejects an access token used as a refresh token', async () => {
      await expectNotAuthenticated(refreshCall(login.accessToken))
    })

    it('rejects a refresh token used as an access token', async () => {
      await expectNotAuthenticated(
        app
          .service('authentication')
          .create({ strategy: 'jwt', accessToken: login.refreshToken }, {}) as Promise<unknown>
      )
    })

    it('rejects expired refresh tokens', async () => {
      const record = store.records.get(hashToken(login.refreshToken))
      record!.expires_at = new Date(Date.now() - 1000)

      await expectNotAuthenticated(refreshCall(login.refreshToken), 'Refresh token has expired')
    })

    it('rejects renewal for inactive users', async () => {
      await setup({
        ...AUTH_CONFIG,
        refresh: {
          ...AUTH_CONFIG.refresh,
          checkUser: (u: unknown) => (u as { status?: string }).status === 'active'
        }
      })
      await expectNotAuthenticated(refreshCall(login.refreshToken), 'User account is not active')
    })

    it('rejects renewal when the user entity cannot be loaded', async () => {
      await app.service('users').remove(user.id)
      await expectNotAuthenticated(refreshCall(login.refreshToken), 'User account is disabled')
    })
  })

  describe('logout', () => {
    beforeEach(() => setup())

    it('revokes the session family', async () => {
      await app
        .service('authentication')
        .remove(null, { authentication: { strategy: 'jwt', accessToken: login.accessToken } })

      const record = await store.findByTokenHash(hashToken(login.refreshToken))
      assert.ok(record?.revoked_at)

      await expectNotAuthenticated(refreshCall(login.refreshToken))
    })
  })

  describe('plugin setup', () => {
    const bareApp = async () => {
      const { feathers } = await import('@feathersjs/feathers')
      const app = feathers()
      app.use('users', { get: async () => ({}), create: async () => ({}), remove: async () => ({}) })
      app.use(
        'authentication',
        new (await import('../src')).RefreshAuthenticationService(app, 'authentication', AUTH_CONFIG)
      )
      return app
    }

    it('throws when no store is configured', async () => {
      const app = await bareApp()
      const { refresh } = await import('../src')
      assert.throws(() => app.configure(refresh()), /no token store configured/)
    })

    it('throws when the authentication service is not a RefreshAuthenticationService', async () => {
      const { feathers } = await import('@feathersjs/feathers')
      const { AuthenticationService } = await import('@feathersjs/authentication')
      const app = feathers()
      app.use('users', { get: async () => ({}), create: async () => ({}), remove: async () => ({}) })
      app.use('authentication', new AuthenticationService(app, 'authentication', AUTH_CONFIG))
      const { refresh } = await import('../src')
      assert.throws(
        () => app.configure(refresh({ store: new MemoryRefreshTokenStore() })),
        /must be an instance/
      )
    })
  })

  describe('MemoryRefreshTokenStore', () => {
    beforeEach(async () => {
      const created = createApp()
      app = created.app
      store = created.store
      user = await createTestUser(app as never)
    })

    it('revokeAllForUser revokes every session of a user', async () => {
      const first = await loginUser(app as never)
      const second = await loginUser(app as never)

      const revoked = await store.revokeAllForUser(String(user.id))
      assert.strictEqual(revoked, 2)
      assert.ok((await store.findByTokenHash(hashToken(first.refreshToken)))?.revoked_at)
      assert.ok((await store.findByTokenHash(hashToken(second.refreshToken)))?.revoked_at)
    })

    it('findActiveByUser only lists active tokens', async () => {
      const firstLogin = await loginUser(app as never)
      await loginUser(app as never)

      // Expire the second token
      const records: RefreshTokenRecord[] = Array.from(store.records.values())
      records[1].expires_at = new Date(Date.now() - 1000)

      const active = await store.findActiveByUser(String(user.id))
      assert.strictEqual(active.length, 1)
      assert.strictEqual(active[0].token_hash, hashToken(firstLogin.refreshToken))
    })

    it('purgeExpired removes expired tokens only', async () => {
      await loginUser(app as never)
      await loginUser(app as never)
      const records = Array.from(store.records.values())
      const [first, second] = records
      first.expires_at = new Date(Date.now() - 5000)

      const purged = await store.purgeExpired(new Date(Date.now() - 1000))
      assert.strictEqual(purged, 1)
      assert.ok(!store.records.has(first.token_hash))
      assert.ok(store.records.has(second.token_hash))
    })
  })
})
