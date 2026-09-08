import assert from 'assert'

import { resolveCookieConfig } from '../src/cookie'

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
  })
})
