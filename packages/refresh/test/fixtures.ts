import { feathers } from '@feathersjs/feathers'
import { memory } from '@feathersjs/memory'
import { LocalStrategy, hooks } from '@feathersjs/authentication-local'
import { JWTStrategy } from '@feathersjs/authentication'

import { RefreshAuthenticationService, MemoryRefreshTokenStore, refresh } from '../src'

export const AUTH_CONFIG = {
  entity: 'user',
  service: 'users',
  secret: 'access-token-secret',
  authStrategies: ['local', 'jwt', 'refresh'],
  local: {
    usernameField: 'email',
    passwordField: 'password'
  },
  refresh: {
    secret: 'refresh-token-secret',
    expiresIn: '1h'
  }
}

export const createApp = (store = new MemoryRefreshTokenStore(), authConfig = AUTH_CONFIG) => {
  const app = feathers()
  app.use('users', memory())
  app.use('protected', {
    async get(id: string, params: any) {
      return { id, params }
    }
  })
  app.use('authentication', new RefreshAuthenticationService(app, 'authentication', authConfig))

  const authService = app.service('authentication') as unknown as RefreshAuthenticationService
  authService.register('local', new LocalStrategy())
  authService.register('jwt', new JWTStrategy())
  app.configure(refresh({ store }))

  app.service('users').hooks({
    before: {
      create: [hooks.hashPassword('password')]
    }
  })

  return { app, store }
}

export const createTestUser = async (app: any, overrides: Record<string, unknown> = {}) => {
  return app.service('users').create({
    email: 'test@example.com',
    password: 'supersecret',
    ...overrides
  })
}

export const loginUser = async (app: any, email = 'test@example.com', password = 'supersecret') => {
  return app.service('authentication').create({ strategy: 'local', email, password }, {})
}
