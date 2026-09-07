# Changelog

## [0.1.0]

### Added

- `RefreshJwtStrategy`: dedicated-secret refresh JWT strategy (`typ: 'refresh'`, body-only).
- `RefreshAuthenticationService`: refresh token issuance on login, `sid` claim on access
  tokens, session-family revocation on logout.
- `RefreshTokenStore` contract (issue, rotate, revokeFamily, revokeAllForUser,
  findActiveByUser, findByTokenHash, findById, purgeExpired).
- `MemoryRefreshTokenStore` in-memory implementation.
- `refresh()` plugin setup helper.
