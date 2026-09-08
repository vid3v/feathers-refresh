import assert from 'assert'
import { feathers } from '@feathersjs/feathers'
import { koa, bodyParser, rest, errorHandler } from '@feathersjs/koa'
import { memory } from '@feathersjs/memory'
import { LocalStrategy, hooks } from '@feathersjs/authentication-local'
import { JWTStrategy } from '@feathersjs/authentication'
import request from 'supertest'
import type { Server } from 'node:http'

import { MemoryRefreshTokenStore, refresh, RefreshAuthenticationService } from '../src'
import { resolveCookieConfig, refreshCookie } from '../src/cookie'

const AUTH_CONFIG = {
  entity: 'user',
  service: 'users',
  secret: 'access-token-secret',
  authStrategies: ['local', 'jwt', 'refresh'],
  local: { usernameField: 'email', passwordField: 'password' },
  refresh: {
    secret: 'refresh-token-secret',
    expiresIn: '1h'
  }
}

const COOKIE_CONFIG = { ...AUTH_CONFIG, refresh: { ...AUTH_CONFIG.refresh, cookie: {} } }

/** Builds a full Koa app with the mandatory middleware order:
 *  errorHandler → bodyParser → refreshCookie → rest. */
const createKoaApp = (authConfig: Record<string, unknown> = COOKIE_CONFIG) => {
  const app = koa(feathers())
  // Production apps sit behind a TLS-terminating proxy; trusting X-Forwarded-Proto
  // lets Koa treat requests as secure so `Secure` cookies can be set over supertest's
  // http loopback (without weakening the cookie attributes).
  app.proxy = true
  app.use(errorHandler())
  app.use(bodyParser())
  app.use(refreshCookie(app))
  app.configure(rest())

  app.use('users', memory())
  app.use('authentication', new RefreshAuthenticationService(app, 'authentication', {
    ...authConfig
  } as never))
  const authService = app.service('authentication') as unknown as RefreshAuthenticationService
  authService.register('local', new LocalStrategy())
  authService.register('jwt', new JWTStrategy())
  app.configure(refresh({ store: new MemoryRefreshTokenStore() }))
  app.service('users').hooks({ before: { create: [hooks.hashPassword('password')] } })
  return app
}

const setupHttp = async (authConfig?: Record<string, unknown>) => {
  const app = createKoaApp(authConfig)
  await (app.service('users') as any).create({
    email: 'test@example.com',
    password: 'supersecret'
  })
  // koa() typing quirk: app.listen returns Promise<Server>; the runtime value is a Server.
  const server = (await app.listen(0)) as unknown as Server
  return { app, server, agent: request(server) }
}

const login = async (agent: ReturnType<typeof request>) => {
  const res = await agent
    .post('/authentication')
    .set('X-Forwarded-Proto', 'https')
    .send({ strategy: 'local', email: 'test@example.com', password: 'supersecret' })
  assert.strictEqual(res.status, 201, `login failed: ${JSON.stringify(res.body)}`)
  return res
}

const setCookieHeader = (res: { headers: Record<string, unknown> }, name = 'refreshToken') => {
  const cookies = res.headers['set-cookie'] as string[] | undefined
  const raw = cookies?.find((cookie) => cookie.startsWith(`${name}=`))
  return raw ?? null
}

const cookiePair = (raw: string) => raw.split(';')[0]

/** Extracts the cookie VALUE from a raw Set-Cookie header (no attributes). */
const cookieValue = (raw: string, name = 'refreshToken') =>
  raw.split(';')[0].slice(name.length + 1)

describe('feathers-authentication-refresh cookie support', () => {
  describe('resolveCookieConfig', () => {
    it('returns null when the refresh.cookie section is absent', () => {
      assert.strictEqual(resolveCookieConfig({}), null)
      assert.strictEqual(resolveCookieConfig({ refresh: { secret: 's', expiresIn: '7d' } }), null)
    })

    it('applies safe defaults from an empty cookie section', () => {
      const config = resolveCookieConfig({ refresh: { secret: 's', expiresIn: '7d', cookie: {} } })
      assert.deepStrictEqual(config, {
        name: 'refreshToken',
        secure: true,
        sameSite: 'lax',
        path: '/authentication',
        maxAge: 7 * 86400000,
        httpOnly: true
      })
    })

    it('honours overrides and derives maxAge from expiresIn', () => {
      const config = resolveCookieConfig({
        refresh: {
          secret: 's',
          expiresIn: '15m',
          cookie: { name: 'rt', secure: false, sameSite: 'strict', path: '/api/auth', domain: 'example.com' }
        }
      })
      assert.deepStrictEqual(config, {
        name: 'rt',
        secure: false,
        sameSite: 'strict',
        path: '/api/auth',
        domain: 'example.com',
        maxAge: 15 * 60000,
        httpOnly: true
      })
    })

    it('returns null on malformed expiresIn even with cookie present', () => {
      assert.strictEqual(resolveCookieConfig({ refresh: { secret: 's', expiresIn: '7x', cookie: {} } }), null)
    })
  })

  describe('refreshCookie middleware — request & response phase', () => {
    let server: Server
    let agent: ReturnType<typeof request>

    beforeEach(async () => {
      const http = await setupHttp()
      server = http.server
      agent = http.agent
    })

    afterEach(() => new Promise<void>((resolve) => server.close(() => resolve())))

    it('login sets the HttpOnly refresh cookie and strips refreshToken from the body', async () => {
      const res = await login(agent)
      const raw = setCookieHeader(res)
      assert.ok(raw, 'expected a Set-Cookie header for refreshToken')
      assert.match(raw, /^refreshToken=ey[^;]+/)
      assert.match(raw, /; HttpOnly/i)
      assert.match(raw, /; Secure/i)
      assert.match(raw, /; SameSite=Lax/i)
      assert.match(raw, /; Path=\/authentication/i)
      // Koa serializes maxAge as an absolute `expires` attribute (no Max-Age header).
      const expiresMatch = raw.match(/; expires=([^;]+)/i)
      assert.ok(expiresMatch, 'expected an expires attribute')
      const maxAgeSeconds = (new Date(expiresMatch[1]).getTime() - Date.now()) / 1000
      assert.ok(maxAgeSeconds > 3500 && maxAgeSeconds <= 3600, `expected ~1h expiry, got ${maxAgeSeconds}s`)
      assert.strictEqual(res.body.refreshToken, undefined)
      assert.ok(typeof res.body.accessToken === 'string')
    })

    it('refreshes from the cookie alone and rotates to a new cookie', async () => {
      const loginRes = await login(agent)
      const loginCookie = setCookieHeader(loginRes)
      assert.ok(loginCookie)

      const res = await agent
        .post('/authentication')
        .set('X-Forwarded-Proto', 'https')
        .set('Cookie', loginCookie)
        .send({ strategy: 'refresh' })

      assert.strictEqual(res.status, 201)
      assert.ok(typeof res.body.accessToken === 'string')
      assert.strictEqual(res.body.refreshToken, undefined, 'rotation response must not leak the token')
      const rotatedCookie = setCookieHeader(res)
      assert.ok(rotatedCookie, 'expected a rotated Set-Cookie')
      assert.notStrictEqual(cookiePair(rotatedCookie), cookiePair(loginCookie), 'token must be rotated')
    })

    it('prefers an explicit body token over the cookie', async () => {
      const loginRes = await login(agent)
      const loginCookie = setCookieHeader(loginRes)
      assert.ok(loginCookie)

      // Rotate once via the cookie, holding the rotated token in the body only.
      const first = await agent
        .post('/authentication')
        .set('X-Forwarded-Proto', 'https')
        .set('Cookie', loginCookie)
        .send({ strategy: 'refresh' })
      assert.strictEqual(first.status, 201)
      const rotatedCookie = setCookieHeader(first)
      assert.ok(rotatedCookie)
      const rotatedToken = cookieValue(rotatedCookie)
      assert.ok(rotatedToken)

      // BOTH channels carry a valid token: body = rotated token, cookie = login token.
      // Body priority means the ROTATED token is consumed (201 + a new cookie).
      const res = await agent
        .post('/authentication')
        .set('X-Forwarded-Proto', 'https')
        .set('Cookie', loginCookie)
        .send({ strategy: 'refresh', refreshToken: rotatedToken })

      assert.strictEqual(res.status, 201, 'the body token must be the one consumed')
      const nextCookie = setCookieHeader(res)
      assert.ok(nextCookie)
      assert.notStrictEqual(cookieValue(nextCookie), rotatedToken, 'a new token must be issued')

      // The family is still alive (no reuse was flagged): the new cookie token rotates.
      const still = await agent
        .post('/authentication')
        .set('X-Forwarded-Proto', 'https')
        .set('Cookie', nextCookie)
        .send({ strategy: 'refresh' })
      assert.strictEqual(still.status, 201)
    })
  })
})
