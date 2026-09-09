import assert from 'assert'
import jsonwebtoken from 'jsonwebtoken'
import { BadRequest, NotFound, NotAuthenticated } from '@feathersjs/errors'
import type { Application } from '@feathersjs/feathers'

import { SessionService, sessions, type SessionView } from '../src'
import { createApp, createTestUser, loginUser } from './fixtures'

/**
 * Emulates what the `authenticate('jwt')` hook puts on params for a JWT request:
 * `params.authentication` (strategy, accessToken, decoded payload) + `params.user`.
 */
const authParams = (accessToken: string) => {
  const payload = jsonwebtoken.decode(accessToken) as { sub: string; sid: string }
  return {
    authentication: { strategy: 'jwt', accessToken, payload },
    user: { id: payload.sub }
  }
}

/** The `sid` (session family id) claim of an access token. */
const sidOf = (accessToken: string) =>
  JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString('utf8')).sid as string

const loginOtherUser = (app: Application) =>
  app
    .service('authentication')
    .create({ strategy: 'local', email: 'other@example.com', password: 'supersecret' }, {}) as Promise<
    Record<string, any>
  >

describe('session service', () => {
  let app: Application
  let store: ReturnType<typeof createApp>['store']
  let user: Record<string, any>

  beforeEach(async () => {
    const created = createApp()
    app = created.app
    store = created.store
    user = await createTestUser(app as never)
    app.configure(sessions())
  })

  // Typed accessor — the registered service instance
  const svc = () => app.service('authentication/sessions') as unknown as SessionService

  describe('find', () => {
    it('requires authentication', async () => {
      try {
        await svc().find({})
        assert.fail('Expected the call to fail')
      } catch (error) {
        assert.ok(error instanceof NotAuthenticated, `Expected NotAuthenticated, got ${error}`)
      }
    })

    it('accepts an internal call with an explicit user', async () => {
      const list = await svc().find({ user: { id: String(user.id) } })
      assert.strictEqual(list.length, 0)

      await loginUser(app as never)

      const after = await svc().find({ user: { id: String(user.id) } })
      assert.strictEqual(after.length, 1)
    })

    it('lists only the active sessions of the authenticated user, without token material', async () => {
      const first = await loginUser(app as never)
      await loginUser(app as never)

      const list = await svc().find(authParams(first.accessToken))

      assert.strictEqual(list.length, 2)
      for (const session of list) {
        assert.strictEqual(session.user_id, String(user.id))
        assert.strictEqual(typeof session.id, 'string')
        assert.ok(session.created_at instanceof Date)
        assert.ok(session.expires_at instanceof Date)
        assert.ok(session.last_used_at instanceof Date)
        assert.ok(!('token_hash' in session))
        assert.ok(!('revoked_at' in session))
        assert.ok(!('replaced_by_id' in session))
      }
      // Newest first
      assert.ok(list[0].created_at.getTime() >= list[1].created_at.getTime())
    })

    it('does not list another user’s sessions', async () => {
      const own = await loginUser(app as never)
      await createTestUser(app as never, { email: 'other@example.com' })
      const other = await loginOtherUser(app as never)

      const ownList = await svc().find(authParams(own.accessToken))
      const otherList = await svc().find(authParams(other.accessToken))

      assert.strictEqual(ownList.length, 1)
      assert.strictEqual(otherList.length, 1)
      assert.notStrictEqual(ownList[0].id, otherList[0].id)
      assert.ok(ownList.every((s) => s.user_id === String(user.id)))
      assert.ok(otherList.every((s) => s.user_id !== String(user.id)))
    })

    it('flags the current session', async () => {
      const first = await loginUser(app as never)
      await loginUser(app as never)

      const list = await svc().find(authParams(first.accessToken))

      assert.strictEqual(list.length, 2)
      assert.strictEqual(list.filter((s) => s.current).length, 1)
      assert.strictEqual(list.find((s) => s.current)!.id, sidOf(first.accessToken))
    })

    it('keeps one row per session family across rotations', async () => {
      const login = await loginUser(app as never)
      const rotated = (await app
        .service('authentication')
        .create({ strategy: 'refresh', refreshToken: login.refreshToken }, {})) as Record<string, any>

      const list = await svc().find(authParams(rotated.accessToken))

      assert.strictEqual(list.length, 1)
      assert.strictEqual(list[0].id, sidOf(login.accessToken))
    })
  })

  describe('remove', () => {
    it('revokes one session by family id', async () => {
      const first = await loginUser(app as never)
      const second = await loginUser(app as never)

      const result = await svc().remove(sidOf(first.accessToken), authParams(second.accessToken))

      assert.strictEqual((result as SessionView).id, sidOf(first.accessToken))
      assert.strictEqual((result as SessionView).user_id, String(user.id))

      const list = await svc().find(authParams(second.accessToken))
      assert.strictEqual(list.length, 1)
      assert.strictEqual(list[0].id, sidOf(second.accessToken))
    })

    it('rejects revoking a session of another user or an unknown session', async () => {
      const own = await loginUser(app as never)
      await createTestUser(app as never, { email: 'other@example.com' })
      const other = await loginOtherUser(app as never)

      try {
        await svc().remove(sidOf(other.accessToken), authParams(own.accessToken))
        assert.fail('Expected the call to fail')
      } catch (error) {
        assert.ok(error instanceof NotFound, `Expected NotFound, got ${error}`)
      }

      try {
        await svc().remove('00000000-0000-0000-0000-000000000000', authParams(own.accessToken))
        assert.fail('Expected the call to fail')
      } catch (error) {
        assert.ok(error instanceof NotFound)
      }

      // The other user's session is untouched
      const otherList = await svc().find(authParams(other.accessToken))
      assert.strictEqual(otherList.length, 1)
    })

    it('rejects a non-string session id', async () => {
      const login = await loginUser(app as never)

      try {
        await svc().remove(42 as never, authParams(login.accessToken))
        assert.fail('Expected the call to fail')
      } catch (error) {
        assert.ok(error instanceof BadRequest, `Expected BadRequest, got ${error}`)
      }
    })

    it('remove(null) revokes every session of the user', async () => {
      const first = await loginUser(app as never)
      const second = await loginUser(app as never)

      const result = (await svc().remove(null, authParams(first.accessToken))) as {
        revoked: number
      }

      assert.strictEqual(result.revoked, 2)

      const remaining = await svc().find(authParams(second.accessToken))
      assert.strictEqual(remaining.length, 0)
    })

    it('treats revoking an already-revoked session as not found', async () => {
      const login = await loginUser(app as never)
      const sid = sidOf(login.accessToken)
      const params = authParams(login.accessToken)

      await svc().remove(sid, params)

      try {
        await svc().remove(sid, params)
        assert.fail('Expected the call to fail')
      } catch (error) {
        assert.ok(error instanceof NotFound)
      }
    })
  })

  describe('plugin setup', () => {
    it('registers under the default path and exposes a SessionService', () => {
      assert.ok(app.service('authentication/sessions') instanceof SessionService)
    })

    it('registers under a custom path', () => {
      const app = createApp().app
      app.configure(sessions({ path: 'my-sessions' }))
      assert.ok(app.service('my-sessions') instanceof SessionService)
    })

    it('uses the store registered by the refresh() plugin', async () => {
      await loginUser(app as never)
      const list = await svc().find({ user: { id: String(user.id) } })
      assert.strictEqual(list.length, 1)
      assert.strictEqual(store.records.size, 1)
    })
  })

  describe('direct service use', () => {
    it('works standalone with an app instance', async () => {
      const standalone = createApp()
      const service = new SessionService(standalone.app)
      await createTestUser(standalone.app as never)
      await loginUser(standalone.app as never)

      const list = await service.find({ user: { id: String(user.id) } })
      assert.strictEqual(list.length, 1)
    })
  })
})
