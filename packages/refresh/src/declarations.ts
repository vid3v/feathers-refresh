import type { Params } from '@feathersjs/feathers'
import type { RefreshTokenStore } from './types'

/**
 * Module augmentation so `app.get('refreshTokenStore')` / `app.set(...)` are typed
 * for consumers of this package.
 */
declare module '@feathersjs/feathers' {
  interface Application<Services = any, Settings = any> {
    get(key: 'refreshTokenStore'): RefreshTokenStore | undefined
    set(key: 'refreshTokenStore', value: RefreshTokenStore): this
  }
}

export type { Params }
