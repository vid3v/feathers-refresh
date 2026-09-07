# Changelog

## [0.1.0]

### Added

- `KnexRefreshTokenStore`: SQL `RefreshTokenStore` adapter with transactional,
  row-locked rotation (`SELECT ... FOR UPDATE` where supported).
- `createRefreshTokensTable` / `dropRefreshTokensTable` migration helpers.
