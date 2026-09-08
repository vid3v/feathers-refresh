# RFC: Refresh token rotation & server-side session revocation for `@feathersjs/authentication`

> Draft issue for `feathersjs/feathers` — review before publishing.
> Suggested title: **RFC: Refresh token rotation & server-side session revocation (working implementation: feathers-authentication-refresh)**

---

## Summary

`@feathersjs/authentication` ships stateless JWT authentication only: there is no
first-party way to issue refresh tokens, rotate them, revoke a session server-side, or
detect token theft. This RFC proposes first-party refresh-token support based on a
working, published implementation — [`feathers-authentication-refresh`](https://github.com/vid3v/feathers-refresh) —
and asks whether the maintainers would consider (a) recommending it as an official
module, or (b) integrating the pattern into `@feathersjs/authentication` via small
extension points.

## The problem

Short-lived access tokens are the recommended setup, but today Feathers apps have no
supported answer to the questions every production API eventually faces:

- *The access token expired — how does the client get a new one without re-sending
  credentials?* (re-authenticating with the long-lived JWT just issues another
  long-lived JWT — [#1338](https://github.com/feathersjs/feathers/issues/1338))
- *The user logs out — how do we actually invalidate the session?* Stateless JWTs stay
  valid until they expire
  ([#1336](https://github.com/feathersjs/feathers/issues/1336),
  [#133](https://github.com/feathersjs-ecosystem/authentication/issues/133),
  [#1417](https://github.com/feathersjs/feathers/issues/1417))
- *A token was stolen — how do we contain the damage?*
- *The password changed / the account was blocked — how do we revoke every session?*

The cookbook's [revoke-jwt](https://feathersjs.com/cookbook/authentication/revoke-jwt.html)
recipe acknowledges the gap and points everyone toward building their own stateful
solution.

## Prior art

- [#1337 — Add support for refresh tokens](https://github.com/feathersjs/feathers/issues/1337):
  open since 2015, still unresolved.
- [PR #2026 — Enable refresh-token server side support](https://github.com/feathersjs/feathers/pull/2026):
  a 2020 attempt to add a `authentication-refresh-token` package. It was closed after
  the maintainer's feedback — quoted here because it defines the path this RFC follows:
  > *"if it can be its own module, it's easier to publish it separately rather than
  > pulling it into the core" (daffl)*
- Community plugins (`@w3lcome/feathers-refresh-token`, `feathers-refresh-token`, ...):
  minimal token swapping, none implement OWASP rotation/reuse-detection, none
  maintained. No clear winner — each app rolls its own.

## The proposal: `feathers-authentication-refresh`

A published, MIT-licensed, CI-tested module ([GitHub](https://github.com/vid3v/feathers-refresh) ·
[npm core](https://www.npmjs.com/package/feathers-authentication-refresh) ·
[npm knex adapter](https://www.npmjs.com/package/feathers-authentication-refresh-knex)),
in production use in a real API since its extraction. It stays as close to the stock
authentication architecture as possible:

```ts
import { refresh, RefreshAuthenticationService } from 'feathers-authentication-refresh'
import { KnexRefreshTokenStore } from 'feathers-authentication-refresh-knex'

// Drop-in replacement for AuthenticationService: mints the refresh token on login,
// adds a `sid` (session family id) claim to access tokens, revokes the session
// family on logout.
app.use('authentication', new RefreshAuthenticationService(app, 'authentication', {
  entity: 'user',
  service: 'users',
  secret: 'access-token-secret',
  authStrategies: ['local', 'jwt', 'refresh'],
  refresh: {
    secret: process.env.AUTH_REFRESH_SECRET, // dedicated signing secret
    expiresIn: '7d',
    sessionStrategies: ['local'],           // which strategies start a session
    checkUser: user => user.status === 'active'
  }
}))

// Registers the `refresh` JWT strategy + the token store (pluggable)
app.configure(refresh({ store: new KnexRefreshTokenStore(knex) }))
```

Flow:

1. `POST /authentication { strategy: 'local', ... }` → `{ accessToken, refreshToken, user }`.
   The access token carries `sid`, the session-family id.
2. `POST /authentication { strategy: 'refresh', refreshToken }` → verifies the refresh
   JWT (dedicated secret, `typ: 'refresh'`), **atomically rotates** it and returns a
   fresh pair.
3. Replaying a consumed token → `NotAuthenticated('Refresh token reuse detected, the
   session has been revoked')` and the **whole family** is invalidated.
4. `DELETE /authentication` → revokes the session family server-side via the access
   token's `sid` claim.

### Security properties (OWASP refresh-token best practices)

- **Rotation is atomic**: transactional store with `SELECT ... FOR UPDATE` on the
  consumed row; concurrent refreshes are serialized, the loser goes through
  reuse detection.
- **Reuse detection**: a replayed token revokes the entire session family (every token
  issued since the original login) — token theft is contained.
- **Hashed at rest**: only `SHA-256(token)` is stored; raw tokens never hit the database.
- **Token type separation**: refresh tokens are signed with a dedicated secret and carry
  `typ: 'refresh'`; access tokens cannot be exchanged at the refresh endpoint and vice
  versa.
- **No header leakage**: the strategy's `parse()` returns `null` — refresh tokens are
  only accepted in the `POST /authentication` body, never as a Bearer header.
- **Real-time safe**: refresh tokens never own socket connections (`handleConnection()`
  is a no-op); access tokens keep doing that.

### Design: pluggable store contract

The DB-agnostic core defines a `RefreshTokenStore` interface
(`issue`, `rotate`, `revokeFamily`, `revokeAllForUser`, `findActiveByUser`,
`findByTokenHash`, `findById`, `purgeExpired`); hashing stays in the core so stores only
ever see hashes. Ships with an in-memory store (tests, small apps) and a Knex adapter
(PostgreSQL/SQLite/MySQL tested); the contract is small enough for D1/Mongo adapters.

The user-facing "may this user renew sessions?" check is a pluggable `checkUser`
predicate (account status, soft-delete, bans...).

## Evidence

- 28 tests covering the flows above (core + SQL adapter, both CI matrix Node 20/22)
- Published on npm, used in production by the author's API (a real multi-tenant
  breeding-management backend) — the module was extracted from it specifically to
  prepare this proposal
- Full disclosure of scope: ~600 lines of core code

## Open questions for the maintainers

1. **Plugin vs core?** Per daffl's feedback on PR #2026, the default answer is "keep it
   a module" — we are fine with that. If so: would the team be open to listing it in
   the docs / ecosystem packages?
2. **Extension points.** Today the module replaces `AuthenticationService` with a
   subclass (to issue refresh tokens in `create()`, add `sid` via `getPayload()`, and
   revoke on `remove()`). It works, but first-class support would avoid subclassing:
   would small upstream hooks be acceptable — e.g. an overridable "session enhancer"
   after login, a way to add claims to the access token payload, and a "logout"
   lifecycle event? We're happy to draft the core PR if the direction is agreed.
3. **Store strategy in core**: is there interest in shipping a reference store (memory)
   with the authentication package itself, with SQL adapters staying external (like
   database adapters do)?
4. **Real-time interplay**: when a session family is revoked mid-connection, should core
   disconnect the socket? That would make revocation effective immediately instead of at
   token expiry — needs a design decision (today we leave connections alone).

## Alternatives considered

- **Opaque (non-JWT) refresh tokens**: strictly simpler and safer (nothing to verify,
  just a lookup) — the module keeps JWT refresh tokens only because it needs zero extra
  infrastructure for the token itself and reuses `createAccessToken`. We'd happily
  follow the maintainers' preference here; the store contract already treats tokens as
  opaque hashes.
- **Do nothing / keep the cookbook approach**: leaves every app to re-implement
  rotation, reuse detection and revocation, with security as the stakes.

---

*Reference implementation links:*
- Repository: https://github.com/vid3v/feathers-refresh
- Core: https://www.npmjs.com/package/feathers-authentication-refresh
- Knex adapter: https://www.npmjs.com/package/feathers-authentication-refresh-knex
- Release: https://github.com/vid3v/feathers-refresh/releases/tag/v0.1.0
