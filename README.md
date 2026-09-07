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

## Development

```bash
npm install
npm test       # compile + run all workspace tests
npm run lint   # prettier + eslint
```

## Roadmap

- [x] Core strategy, service, store contract, memory store
- [x] Knex adapter + migration helpers
- [ ] HTTP-only cookie helpers for refresh tokens
- [ ] Session listing / per-session revocation service
- [ ] Expired-token purge job
- [ ] Other store adapters (D1, Mongo, ...)

## Contributing upstream

The long-term goal of this project is to propose refresh-token support upstream to
`feathersjs/feathers`. Keeping the store DB-agnostic and the strategy free of
application assumptions is a deliberate design choice for that RFC.

## License

MIT — see [LICENSE](./LICENSE).
