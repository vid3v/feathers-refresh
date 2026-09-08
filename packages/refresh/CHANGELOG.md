# Changelog

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
