/**
 * A stored refresh token record. Stores never see raw tokens, only their SHA-256 hash
 * (see `hashToken`). Field names use snake_case so SQL adapters can map them directly
 * to table columns.
 */
export interface RefreshTokenRecord {
  id: string
  /** Identifies the session family — shared by every token issued during one login session. */
  family_id: string
  user_id: string
  /** SHA-256 hash of the raw refresh token. */
  token_hash: string
  expires_at: Date
  user_agent: string | null
  ip_address: string | null
  revoked_at: Date | null
  /** The record that replaced this one after rotation. */
  replaced_by_id: string | null
  created_at: Date
  updated_at: Date
}

export interface IssueRefreshTokenInput {
  user_id: string
  family_id: string
  token_hash: string
  expires_at: Date
  user_agent?: string | null
  ip_address?: string | null
}

export interface RotateRefreshTokenInput extends IssueRefreshTokenInput {
  /** Hash of the token being consumed. */
  oldTokenHash: string
}

export type RotateResult =
  | { ok: true; record: RefreshTokenRecord; familyId: string }
  | { ok: false; reason: 'invalid' | 'expired' | 'reused'; familyId?: string; userId?: string }

/**
 * Data access contract for refresh token persistence.
 *
 * Implementations must guarantee:
 * - `rotate` is atomic: concurrent rotations of the same token are serialized, the
 *   loser is treated as a reuse.
 * - presenting an already revoked token to `rotate` fails with reason `reused`
 *   (the caller revokes the whole family in that case).
 *
 * Hashing stays in the core package (`hashToken`) — stores only ever receive hashes.
 */
export interface RefreshTokenStore {
  issue(input: IssueRefreshTokenInput): Promise<RefreshTokenRecord>

  /**
   * Atomically consumes `oldTokenHash` and registers its replacement.
   * Throws is not expected — failures are reported through the `RotateResult`.
   */
  rotate(input: RotateRefreshTokenInput): Promise<RotateResult>

  /** Revokes every non-revoked token of one session family. Returns the number of rows updated. */
  revokeFamily(familyId: string, userId?: string): Promise<number>

  /** Revokes every session of a user (password change, account deactivation). */
  revokeAllForUser(userId: string): Promise<number>

  /** Lists every active session of one user (one row per non-revoked, non-expired token). */
  findActiveByUser(userId: string): Promise<RefreshTokenRecord[]>

  /** Finds a record by its token hash, including revoked ones (needed for reuse detection). */
  findByTokenHash(tokenHash: string): Promise<RefreshTokenRecord | undefined>

  /** Finds a record by its primary key, including revoked ones (session management views). */
  findById(id: string): Promise<RefreshTokenRecord | undefined>

  /** Deletes tokens expired since longer than `olderThan` (audit retention window). */
  purgeExpired(olderThan: Date): Promise<number>
}

/**
 * `authentication.refresh` configuration section.
 */
export interface RefreshConfig {
  /** Dedicated signing secret for refresh JWTs. MUST differ from the access token secret. */
  secret: string
  /** Refresh token lifetime, e.g. `'7d'`, `'12h'`. */
  expiresIn: string
  /**
   * Login strategies that start a refresh-token session (an access token with a `sid`
   * claim plus a refresh token are issued). Defaults to `['local']`.
   */
  sessionStrategies?: string[]
  /**
   * Optional predicate deciding whether the resolved user may renew sessions
   * (e.g. check `status === 'active' && deleted_at == null`). Defaults to allowing everyone.
   */
  checkUser?: (user: unknown) => boolean | Promise<boolean>
  /**
   * Enables HTTP-only cookie support for the refresh token when present
   * (`cookie: {}` uses all defaults). Handled by the `refreshCookie()` Koa
   * middleware — the service and strategies are unchanged.
   */
  cookie?: RefreshCookieConfig
}

export interface RefreshRequestMeta {
  user_agent: string | null
  ip_address: string | null
}

/**
 * `authentication.refresh.cookie` configuration section.
 * The mere presence of this section enables HTTP-only cookie support.
 * Only safe overridable attributes are exposed: `httpOnly` is always `true`
 * and `maxAge` is always derived from `refresh.expiresIn`.
 */
export interface RefreshCookieConfig {
  /** Cookie name. Defaults to `'refreshToken'`. */
  name?: string
  /** `Secure` attribute. Defaults to `true` (set `false` for local http dev only). */
  secure?: boolean
  /** `SameSite` attribute. Defaults to `'lax'` (CSRF-safe for the refresh POST). */
  sameSite?: 'lax' | 'strict' | 'none'
  /**
   * Cookie `Path` attribute AND the request path the middleware matches
   * (`ctx.path`, trailing slashes normalized). Defaults to `'/authentication'`.
   */
  path?: string
  /** `Domain` attribute. Defaults to unset (host-only cookie). */
  domain?: string
}
