# Changelog

## [0.3.0] - 2026-09-09

### Added

- Session listing / per-session revocation service: `SessionService` + `sessions()`
  plugin (default path `authentication/sessions`). `find` lists the authenticated
  user's active sessions (one row per session family, `current` flag, no token
  material exposed), `remove(id)` revokes one session family, `remove(null)` revokes
  every session of the user ("log out everywhere"). Access is always scoped to the
  verified JWT `sub` (or an explicit internal `params.user`).
- `SessionView` and `SessionParams` types.

## [0.2.0] - 2026-09-08

### Added

- HTTP-only cookie support for refresh tokens: `refreshCookie()` Koa middleware +
  `refresh.cookie` configuration section (rotation, reuse detection and logout
  revocation work unchanged; the refresh token never reaches browser JavaScript).
- `RefreshCookieConfig` type with safe defaults (`HttpOnly` forced, `Secure`,
  `SameSite=Lax`, `Path=/authentication`, lifetime derived from `refresh.expiresIn`).

## [0.1.0]

### Added

- `RefreshJwtStrategy`: dedicated-secret refresh JWT strategy (`typ: 'refresh'`, body-only).
- `RefreshAuthenticationService`: refresh token issuance on login, `sid` claim on access
  tokens, session-family revocation on logout.
- `RefreshTokenStore` contract (issue, rotate, revokeFamily, revokeAllForUser,
  findActiveByUser, findByTokenHash, findById, purgeExpired).
- `MemoryRefreshTokenStore` in-memory implementation.
- `refresh()` plugin setup helper.
