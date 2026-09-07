import type { Application } from '@feathersjs/feathers'

import { RefreshAuthenticationService } from './service'
import { RefreshJwtStrategy, setRefreshTokenStore } from './strategy'
import type { RefreshTokenStore } from './types'

export interface RefreshPluginOptions {
  /** The token store implementation to use (e.g. the Knex adapter's store). */
  store?: RefreshTokenStore
  /** Name the refresh strategy registers itself under. Defaults to `'refresh'`. */
  name?: string
}

/**
 * Registers the `refresh` JWT strategy and the token store on the app:
 *
 * ```ts
 * import { refresh } from 'feathers-authentication-refresh'
 * import { KnexRefreshTokenStore } from 'feathers-authentication-refresh-knex'
 *
 * // The authentication service MUST be a RefreshAuthenticationService
 * app.use('/authentication', new RefreshAuthenticationService(app, 'authentication', {
 *   entity: 'user',
 *   service: 'users',
 *   secret: 'supersecret',
 *   authStrategies: ['local', 'jwt', 'refresh'],
 *   refresh: {
 *     secret: process.env.AUTH_REFRESH_SECRET,
 *     expiresIn: '7d'
 *   }
 * }))
 *
 * app.configure(refresh({ store: new KnexRefreshTokenStore(knex) }))
 * ```
 */
export const refresh = (options: RefreshPluginOptions = {}) => (app: Application) => {
  const store = options.store ?? app.get('refreshTokenStore')
  if (!store) {
    throw new Error(
      'feathers-authentication-refresh: no token store configured. ' +
        'Pass one via refresh({ store }) — e.g. new KnexRefreshTokenStore(knex) from the knex adapter package.'
    )
  }
  setRefreshTokenStore(app, store)

  const authService = app.service('authentication')
  if (!(authService instanceof RefreshAuthenticationService)) {
    throw new Error(
      'feathers-authentication-refresh: the /authentication service must be an instance of ' +
        "RefreshAuthenticationService (imported from 'feathers-authentication-refresh') " +
        'so that login issues refresh tokens and logout revokes the session family.'
    )
  }

  authService.register(options.name ?? 'refresh', new RefreshJwtStrategy())
}
