# Changelog

## [0.2.0] - 2026-09-09

### Changed

- `findActiveByUser` now selects `updated_at` (backs the `last_used_at` field of the
  core package's session service view).
- Peer/dev dependency range for `feathers-authentication-refresh` widened to
  `^0.1.0 || ^0.2.0 || ^0.3.0` (accepts the 0.3.0 sessions-service release).

### Fixed

- Test suite converted to a static `knex` import (pre-existing eslint
  `no-var-requires` violation).

## [0.1.1]

### Changed

- Peer/dev dependency range for `feathers-authentication-refresh` widened to
  `^0.1.0 || ^0.2.0` (accepts the 0.2.0 cookie-support release). No code changes.

## [0.1.0]

### Added

- `KnexRefreshTokenStore`: SQL `RefreshTokenStore` adapter with transactional,
  row-locked rotation (`SELECT ... FOR UPDATE` where supported).
- `createRefreshTokensTable` / `dropRefreshTokensTable` migration helpers.
