// Intentionally no module augmentation here: augmenting `Application.get/set` for the
// 'refreshTokenStore' key would shadow the inherited generic signatures. Store access
// goes through `getRefreshTokenStore(app)` / `setRefreshTokenStore(app, store)` instead.

export {}
