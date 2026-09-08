# Changelog

## [0.1.1]

### Changed

- Peer/dev dependency range for `feathers-authentication-refresh` widened to
  `^0.1.0 || ^0.2.0` (accepts the 0.2.0 cookie-support release). No code changes.

## [0.1.0]

### Added

- `KnexRefreshTokenStore`: SQL `RefreshTokenStore` adapter with transactional,
  row-locked rotation (`SELECT ... FOR UPDATE` where supported).
- `createRefreshTokensTable` / `dropRefreshTokensTable` migration helpers.
