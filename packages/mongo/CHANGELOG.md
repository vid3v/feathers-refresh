# Changelog

## [0.1.0]

### Added

- `MongoRefreshTokenStore`: MongoDB `RefreshTokenStore` adapter with atomic,
  transaction-free rotation (conditional `updateOne` claim — no multi-document
  transactions or replica set required).
- `createRefreshTokensIndexes` / `dropRefreshTokensCollection` setup helpers
  (unique index on `token_hash`, lookup indexes on `user_id` / `family_id` /
  `expires_at`).
