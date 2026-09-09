# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-09-09

### Added

- Session listing / per-session revocation service (`feathers-authentication-refresh`
  0.3.0): `sessions()` plugin + `SessionService` — `find` lists the authenticated
  user's active sessions (one row per session family, `current` flag, no token
  material exposed), `remove(id)` revokes one session family, `remove(null)` revokes
  every session of the user ("log out everywhere"). Scoped to the verified JWT `sub`
  (or an explicit internal `params.user`).
- `SessionView` and `SessionParams` types.

### Changed

- knex adapter (`feathers-authentication-refresh-knex`, released as 0.2.0):
  `findActiveByUser` now selects `updated_at` (backs the session view's
  `last_used_at`) and its peer/dev range was widened to `^0.1.0 || ^0.2.0 || ^0.3.0`.

## [0.2.0] - 2026-09-08

### Added

- HTTP-only cookie support for refresh tokens: `refreshCookie()` Koa middleware +
  `refresh.cookie` configuration section (rotation, reuse detection and logout
  revocation work unchanged; the refresh token never reaches browser JavaScript).
- `RefreshCookieConfig` type with safe defaults (`HttpOnly` forced, `Secure`,
  `SameSite=Lax`, `Path=/authentication`, lifetime derived from `refresh.expiresIn`).

### Changed

- knex adapter (`feathers-authentication-refresh-knex`, released as 0.1.1): peer/dev
  range widened to `^0.1.0 || ^0.2.0` to accept this release.

## [0.1.0] - 2026-02-14

### Added

- `feathers-authentication-refresh` core package: `RefreshJwtStrategy`,
  `RefreshAuthenticationService`, `RefreshTokenStore` contract,
  `MemoryRefreshTokenStore`, `refresh()` plugin setup helper.
- `feathers-authentication-refresh-knex` adapter: `KnexRefreshTokenStore`,
  `createRefreshTokensTable` / `dropRefreshTokensTable` migration helpers.
- Full test suite (core + knex/sqlite) and CI workflow.
