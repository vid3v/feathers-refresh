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

app.configure(refresh({ store: new KnexRefreshTokenStore(database) }))
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
`domain`. `path` is both the cookie `Path` attribute and the request path the
middleware matches — widening it (e.g. `'/'`) widens the request matching too.
`httpOnly` is always `true` and the cookie lifetime always follows
`refresh.expiresIn`.

An explicit body `refreshToken` always wins over the cookie, so existing body-based
clients keep rotating without changes. Note that in cookie mode the refresh token is
never returned in the JSON body — clients that don't persist `Set-Cookie` headers
(e.g. many native HTTP stacks) must therefore either keep cookie support disabled or
rely on their cookie jar.

## Session management

The optional sessions service exposes the active sessions of the **authenticated user**
(listing, per-session revocation, "log out everywhere") on top of any store:

```ts
import { refresh, sessions } from 'feathers-authentication-refresh'

app.configure(refresh({ store: new KnexRefreshTokenStore(database) }))
app.configure(sessions()) // → /authentication/sessions
app.service('authentication/sessions').hooks({
  before: { all: authenticate('jwt') }
})
```

- `find()` → the active sessions of the caller, one row per session family, newest
  first: `{ id /* = sid claim */, user_agent, ip_address, created_at, expires_at,
  last_used_at, current }`. Sensitive store fields (`token_hash`, `revoked_at`,
  `replaced_by_id`) are never exposed. The request's own session carries `current: true`.
- `remove(sid)` → revokes one session family (its refresh token becomes unusable; the
  already-issued access token simply expires — same semantics as logout).
- `remove(null)` → revokes **every** session of the user ("log out everywhere") and
  returns `{ revoked }`.

Everything is scoped to the authenticated user (resolved from the verified JWT `sub`,
or an explicit internal `params.user`) — nobody can list or revoke another user's
sessions, and unknown or foreign session ids return the same `NotFound`.

## Expired-token purge job

Without cleanup, consumed/expired refresh-token rows accumulate forever in SQL stores.
The optional purge job deletes **expired** rows on a schedule using any store's
`purgeExpired` (active and revoked-but-unexpired rows are never touched; audit history
is governed by the retention window):

```ts
import { refresh, purgeJob } from 'feathers-authentication-refresh'

app.configure(refresh({ store }))
app.configure(purgeJob({ interval: '6h', olderThan: '30d' }))
```

- `interval` (default `'24h'`) — how often the job runs (`'15m'`, `'1h'`, ...).
- `olderThan` (default `'0s'`) — retention window: only tokens expired since longer
  than this are deleted, so recently expired rows stay queryable for audits.
- `runOnStart` (default `false`) — runs one pass immediately at startup.
- `onError` — called when a scheduled run fails (default `console.error`), so a
  transient store outage never kills the schedule.

Or start it in one step with the store registration:

```ts
app.configure(refresh({ store, purge: { interval: '6h', olderThan: '30d' } }))
```

The handle is available as `app.get('refreshPurgeJob')` — `run()` triggers a pass
immediately (resolves with the number of deleted rows), `stop()` cancels the schedule
for graceful shutdown. The underlying timer is `unref`'d, so the job never keeps the
process alive on its own.

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
- [x] Session listing / per-session revocation service
- [x] Expired-token purge job
- [ ] Other store adapters (D1, Mongo, ...)

## Contributing upstream

The long-term goal of this project is to propose refresh-token support upstream to
`feathersjs/feathers`. Keeping the store DB-agnostic and the strategy free of
application assumptions is a deliberate design choice for that RFC.

## License

MIT — see [LICENSE](./LICENSE).
