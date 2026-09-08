# feathers-refresh

Refresh token rotation, session revocation and reuse detection for
[FeathersJS](https://feathersjs.com) authentication.

`@feathersjs/authentication` ships access-token (JWT) authentication but no first-party
support for refresh tokens and server-side session management. This monorepo provides it
as a set of small, pluggable packages following the OWASP refresh-token best practices:

| Package | Description |
| --- | --- |
| [`feathers-authentication-refresh`](./packages/refresh) | Core: `refresh` JWT strategy, `RefreshAuthenticationService`, store contract, in-memory store |
| [`feathers-authentication-refresh-knex`](./packages/knex) | Knex adapter (PostgreSQL, SQLite, MySQL, ...) + migration helpers |

## Security model

- **Short-lived access tokens** (e.g. 15 min) + **long-lived refresh tokens** (e.g. 7 days).
- **Rotation**: every refresh consumes the old token and issues a new pair. Rotation is
  atomic (`SELECT ... FOR UPDATE` in the SQL adapter), so concurrent refreshes are serialized.
- **Reuse detection**: replaying an already-consumed refresh token is treated as token theft
  and revokes the **whole session family** — every token issued since the original login.
- **Hashed at rest**: only `SHA-256(token)` is stored, never the raw token.
- **Token type separation**: refresh tokens are signed with a dedicated secret and carry
  `typ: 'refresh'`; access tokens can never be exchanged at the refresh endpoint and vice versa.
- **No header leakage**: refresh tokens are only accepted in the `POST /authentication`
  body, never as a `Bearer` header.
- **Logout revokes the session family** server-side through the `sid` claim on access tokens.

## Quickstart

```bash
npm install feathers-authentication-refresh feathers-authentication-refresh-knex knex
```

```ts
import { knex } from 'knex'
import { refresh, RefreshAuthenticationService } from 'feathers-authentication-refresh'
import {
  KnexRefreshTokenStore,
  createRefreshTokensTable
} from 'feathers-authentication-refresh-knex'

const database = knex({ client: 'pg', connection: process.env.DATABASE_URL })
await createRefreshTokensTable(database)

app.use('authentication', new RefreshAuthenticationService(app, 'authentication', {
  entity: 'user',
  service: 'users',
  secret: 'access-token-secret',
  authStrategies: ['local', 'jwt', 'refresh'],
  refresh: {
    // Dedicated secret — MUST differ from the access token secret
    secret: process.env.AUTH_REFRESH_SECRET,
    expiresIn: '7d'
  }
}))
app.configure(refresh({ store: new KnexRefreshTokenStore(database) }))
```

Client flow:

```js
// 1. login
const { accessToken, refreshToken } = await client.authenticate({
  strategy: 'local',
  email,
  password
})

// 2. when the access token expires
const rotated = await client.authenticate({
  strategy: 'refresh',
  refreshToken // persist the NEW refreshToken from the response
})

// 3. logout (revokes the whole session family server-side)
await client.logout()
```

## HTTP-only cookie support

For browser clients, the refresh token can be moved into an `HttpOnly` cookie so
JavaScript never sees it (XSS can no longer exfiltrate it):

```ts
import { refresh, RefreshAuthenticationService, refreshCookie } from 'feathers-authentication-refresh'

app.use('authentication', new RefreshAuthenticationService(app, 'authentication', {
  // ...existing config
  refresh: {
    secret: process.env.AUTH_REFRESH_SECRET,
    expiresIn: '7d',
    cookie: {} // presence enables cookie support; all attributes have safe defaults
  }
}))

// Mandatory position: after bodyParser(), before rest()
app.use(refreshCookie(app))

app.configure(refresh({ store: new KnexRefreshTokenStore(knex) }))
```

Browser flow:

1. **Login** → response body `{ accessToken, user }` (no refresh token in JSON) +
   `Set-Cookie: refreshToken=…; HttpOnly; Secure; SameSite=Lax; Path=/authentication`
2. **Refresh** → `POST /authentication { strategy: 'refresh' }` — the cookie is sent
   automatically, no token in the body needed
3. **Logout** → `DELETE /authentication` — the session family is revoked and the
   cookie is cleared

Defaults (overridable via `refresh.cookie`): `name: 'refreshToken'`,
`secure: true` (set `false` for local http dev), `sameSite: 'lax'` (blocks cross-site
POSTs — CSRF-safe on modern browsers; use `'strict'` for more), `path` /
`domain`. `httpOnly` is always `true` and the cookie lifetime always follows
`refresh.expiresIn`.

Non-cookie clients (native apps) keep working unchanged: an explicit body
`refreshToken` always wins over the cookie, so one deployment serves both.

## Development

```bash
npm install
npm test       # compile + run all workspace tests
npm run lint   # prettier + eslint
```

## Roadmap

- [x] Core strategy, service, store contract, memory store
- [x] Knex adapter + migration helpers
- [x] HTTP-only cookie helpers for refresh tokens
- [ ] Session listing / per-session revocation service
- [ ] Expired-token purge job
- [ ] Other store adapters (D1, Mongo, ...)

## Contributing upstream

The long-term goal of this project is to propose refresh-token support upstream to
`feathersjs/feathers`. Keeping the store DB-agnostic and the strategy free of
application assumptions is a deliberate design choice for that RFC.

## License

MIT — see [LICENSE](./LICENSE).
