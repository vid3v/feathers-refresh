# feathers-authentication-refresh

Refresh token rotation, session revocation and reuse detection for FeathersJS
authentication. This is the core package: a DB-agnostic strategy + service and the
`RefreshTokenStore` contract — plus optional HTTP-only cookie support for the refresh
token (`refreshCookie()` middleware + `refresh.cookie` config section).

> See the [monorepo README](../../README.md) for the full security model and the
> [HTTP-only cookie support](../../README.md#http-only-cookie-support) section.

## Install

```bash
npm install feathers-authentication-refresh
```

You also need a store — use [`feathers-authentication-refresh-knex`](../knex) for SQL
databases or the built-in `MemoryRefreshTokenStore` for tests and lightweight apps.

## Usage

```ts
import { feathers } from '@feathersjs/feathers'
import { refresh, RefreshAuthenticationService } from 'feathers-authentication-refresh'

app.use('authentication', new RefreshAuthenticationService(app, 'authentication', {
  entity: 'user',
  service: 'users',
  secret: 'access-token-secret',
  authStrategies: ['local', 'jwt', 'refresh'],
  refresh: {
    secret: process.env.AUTH_REFRESH_SECRET, // dedicated signing secret
    expiresIn: '7d',
    // optional:
    sessionStrategies: ['local'],            // strategies that start a session (default: ['local'])
    checkUser: (user) => user.status === 'active' // gate session renewal
  }
}))
app.configure(refresh({ store: new KnexRefreshTokenStore(knex) }))
```

The authentication service **must** be a `RefreshAuthenticationService` (the plugin
throws otherwise): it is what mints the refresh token on login, adds the `sid` claim
to access tokens and revokes the session family on logout.

## How it works

1. `POST /authentication { strategy: 'local', ... }` — returns `{ accessToken,
   refreshToken, user }`. The access token payload carries `sid`, the session family id.
2. `POST /authentication { strategy: 'refresh', refreshToken }` — verifies the refresh
   JWT (dedicated secret, `typ: 'refresh'`), then atomically rotates it through the
   store and returns a fresh pair.
3. Replaying a consumed token → `NotAuthenticated('Refresh token reuse detected, the
   session has been revoked')` and the whole family is invalidated.
4. `DELETE /authentication` — verifies the access token and revokes its session family.

## `RefreshTokenStore` contract

Stores never see raw tokens — only their SHA-256 hashes (`hashToken` from this package):

```ts
interface RefreshTokenStore {
  issue(input: IssueRefreshTokenInput): Promise<RefreshTokenRecord>
  rotate(input: RotateRefreshTokenInput): Promise<RotateResult>
  revokeFamily(familyId: string, userId?: string): Promise<number>
  revokeAllForUser(userId: string): Promise<number>
  findActiveByUser(userId: string): Promise<RefreshTokenRecord[]>
  findByTokenHash(tokenHash: string): Promise<RefreshTokenRecord | undefined>
  findById(id: string): Promise<RefreshTokenRecord | undefined>
  purgeExpired(olderThan: Date): Promise<number>
}
```

`rotate` must be atomic and must report `reused` when an already-revoked token is
presented. Implement this interface to support another database.

## License

MIT
