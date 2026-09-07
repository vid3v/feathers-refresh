import { NotAuthenticated } from '@feathersjs/errors'
import { AuthenticationBaseStrategy } from '@feathersjs/authentication'
import type { AuthenticationParams, AuthenticationRequest, JwtVerifyOptions } from '@feathersjs/authentication'
import type { Application } from '@feathersjs/feathers'

import type { RefreshConfig, RefreshTokenStore } from './types'
import { hashToken, parseExpiresIn, requestMeta } from './utils'

/** Reads the `authentication.refresh` configuration section, with defaults. */
export const getRefreshConfig = (authConfig: Record<string, unknown>): Required<Pick<RefreshConfig, 'sessionStrategies'>> & RefreshConfig => {
  const refresh = authConfig.refresh as Partial<RefreshConfig> | undefined
  if (!refresh?.secret || !refresh?.expiresIn) {
    throw new Error(
      "Missing 'authentication.refresh' configuration (secret, expiresIn). " +
        'Set the refresh token secret and lifetime (e.g. AUTH_REFRESH_SECRET, refresh.expiresIn: "7d").'
    )
  }
  return {
    sessionStrategies: ['local'],
    ...refresh
  } as Required<Pick<RefreshConfig, 'sessionStrategies'>> & RefreshConfig
}

const REFRESH_STORE_KEY = 'refreshTokenStore'

/** Resolves the refresh token store registered on the app (via the `refresh` plugin). */
export const getRefreshTokenStore = (app: Application): RefreshTokenStore => {
  const store = app.get(REFRESH_STORE_KEY) as RefreshTokenStore | undefined
  if (!store) {
    throw new Error(
      'No refresh token store configured. Call app.configure(refresh({ store })) or ' +
        'app.set("refreshTokenStore", store) before authenticating.'
    )
  }
  return store
}

export const setRefreshTokenStore = (app: Application, store: RefreshTokenStore): void => {
  app.set(REFRESH_STORE_KEY, store)
}

/**
 * JWT strategy for refresh tokens, registered under the `refresh` name.
 *
 * Security properties:
 *  - refresh JWTs are signed with a dedicated secret (`authentication.refresh.secret`) and
 *    carry `typ: 'refresh'` in the payload — an access token can never be exchanged here,
 *    and a refresh token can never be used as an access token (the two secrets differ too).
 *  - HTTP header parsing is disabled: refresh tokens are only accepted in the
 *    `POST /authentication` body, never as a Bearer token on data endpoints.
 *  - rotation is delegated to the configured {@link RefreshTokenStore} which must be
 *    atomic; replaying an already consumed token revokes the whole session family.
 */
export class RefreshJwtStrategy extends AuthenticationBaseStrategy {
  verifyConfiguration(): void {
    // The base implementation rejects any configuration key outside
    // ['entity', 'entityId', 'service', 'header', 'schemes']. The `authentication.refresh`
    // section legitimately holds `secret`, `expiresIn` and friends, so the allow-list is skipped.
  }

  async parse(): Promise<null> {
    return null
  }

  async handleConnection(): Promise<void> {
    // Refresh tokens never own real-time connections — access tokens do.
  }

  async authenticate(authentication: AuthenticationRequest, params: AuthenticationParams) {
    const authService = this.authentication
    const app = this.app
    if (!authService || !app) {
      throw new NotAuthenticated('Refresh strategy is not initialised')
    }

    const { refreshToken } = authentication as { refreshToken?: unknown }

    if (typeof refreshToken !== 'string' || refreshToken.length === 0) {
      throw new NotAuthenticated('A refresh token is required')
    }

    const authConfig = authService.configuration as Record<string, unknown>
    const { secret, expiresIn, checkUser } = getRefreshConfig(authConfig)
    const store = getRefreshTokenStore(app)

    // Verify signature & expiry of the *refresh* token using the dedicated secret.
    let payload: Record<string, unknown>
    try {
      payload = (await authService.verifyAccessToken(
        refreshToken,
        { algorithms: ['HS256'] } as JwtVerifyOptions,
        secret
      )) as Record<string, unknown>
    } catch {
      // Malformed, wrongly signed or structurally invalid tokens all get the same response.
      throw new NotAuthenticated('Invalid refresh token')
    }

    if (payload?.typ !== 'refresh' || typeof payload?.sid !== 'string' || typeof payload?.sub !== 'string') {
      throw new NotAuthenticated('Invalid refresh token')
    }
    const sid = payload.sid
    const subject = payload.sub

    // Resolve the user via the configured entity service (internal call, provider stripped
    // so auth hooks are skipped).
    const serviceName = authConfig.service as string | undefined
    const entityService = serviceName ? app.service(serviceName) : undefined
    if (!entityService) {
      throw new NotAuthenticated('Could not find the user entity service')
    }

    let user: unknown
    try {
      user = await entityService.get(subject, { query: {} })
    } catch {
      throw new NotAuthenticated('User account is disabled')
    }

    // An application-specific check (blocked, soft-deleted, ...) may prevent session renewal.
    if (checkUser && !(await checkUser(user))) {
      throw new NotAuthenticated('User account is not active')
    }

    const meta = requestMeta(params as unknown as { headers?: Record<string, string | string[] | undefined> })

    // Issue the new refresh token first so its hash can be stored atomically during
    // rotation (see the store's `rotate`).
    const expiresAt = new Date(Date.now() + parseExpiresIn(expiresIn) * 1000)
    const newRefreshToken = await authService.createAccessToken(
      { sid, typ: 'refresh' },
      {
        subject,
        expiresIn,
        algorithm: 'HS256'
      } as never,
      secret
    )

    // Atomic rotation: the store reports unknown/expired/revoked tokens; on reuse the
    // whole session family must be revoked.
    const result = await store.rotate({
      oldTokenHash: hashToken(refreshToken),
      token_hash: hashToken(newRefreshToken),
      user_id: subject,
      family_id: sid,
      expires_at: expiresAt,
      ...meta
    })

    if (!result.ok) {
      if (result.reason === 'reused') {
        // Revocation happens outside the rotation transaction (it was rolled back there).
        await store.revokeFamily(result.familyId as string, result.userId)
        throw new NotAuthenticated('Refresh token reuse detected, the session has been revoked')
      }
      if (result.reason === 'expired') {
        throw new NotAuthenticated('Refresh token has expired')
      }
      throw new NotAuthenticated('Invalid refresh token')
    }

    return {
      authentication: {
        strategy: this.name,
        payload
      },
      refreshToken: newRefreshToken,
      [(authConfig.entity as string) ?? 'user']: user
    }
  }
}
