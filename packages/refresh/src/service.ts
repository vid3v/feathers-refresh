import { randomUUID } from 'node:crypto'
import { AuthenticationService } from '@feathersjs/authentication'
import type { AuthenticationParams, AuthenticationRequest } from '@feathersjs/authentication'
import type { Application } from '@feathersjs/feathers'

import { getRefreshConfig, getRefreshTokenStore } from './strategy'
import { hashToken, parseExpiresIn, requestMeta } from './utils'

/**
 * Drop-in replacement for the stock Feathers `AuthenticationService` that adds
 * refresh tokens on top of any login strategy:
 *
 * - `POST /authentication { strategy: 'local' }` (or any strategy listed in
 *   `authentication.refresh.sessionStrategies`) issues an access token **and** a refresh
 *   token. The access token carries a `sid` claim identifying the session family.
 * - `POST /authentication { strategy: 'refresh', refreshToken }` rotates the session:
 *   a new access token and a new refresh token are issued and the old refresh token is
 *   revoked atomically (with reuse detection revoking the whole session family — see
 *   {@link RefreshJwtStrategy}).
 * - `DELETE /authentication` (logout) revokes the whole session family identified by
 *   the access token's `sid` claim.
 */
export class RefreshAuthenticationService extends AuthenticationService {
  /**
   * Adds the current session id (`sid` claim) to access tokens. This is what lets
   * logout and "revoke my current session" work without the client sending the
   * refresh token.
   */
  override async getPayload(
    authResult: Record<string, unknown>,
    params: AuthenticationParams
  ): Promise<Record<string, unknown>> {
    const base = await super.getPayload(authResult as never, params)
    // - login: `refreshSid` was put on params by `create` before minting the token
    // - refresh flow: the presented refresh token's payload carries the session family id
    const sid =
      (params as { refreshSid?: string } | undefined)?.refreshSid ??
      (authResult?.authentication as { payload?: { sid?: string } } | undefined)?.payload?.sid
    return sid ? { ...base, sid } : base
  }

  override async create(data: AuthenticationRequest, params?: AuthenticationParams) {
    const authConfig = this.configuration as Record<string, unknown>
    const strategy = data?.strategy

    if (strategy === 'refresh') {
      // The strategy performed the rotation (revoke old, insert new, reuse detection)
      // already; just hand the result through.
      return super.create(data, (params as AuthenticationParams) ?? {})
    }

    const { sessionStrategies } = getRefreshConfig(authConfig)
    if (!sessionStrategies.includes(strategy as string)) {
      // Delegate anything else (JWT re-authentication, oauth, ...) to the base implementation.
      return super.create(data, (params as AuthenticationParams) ?? {})
    }

    // A fresh session id is generated up-front and added to the access token payload
    // through `getPayload` (see `refreshSid` above).
    const sid = randomUUID()
    const paramsWithSid = { ...(params ?? {}), refreshSid: sid } as AuthenticationParams

    const result = (await super.create(data, paramsWithSid)) as Record<string, unknown> & {
      authentication?: { strategy?: string; payload?: Record<string, unknown> }
      refreshToken?: string
    }

    const entity = (authConfig.entity as string) ?? 'user'
    const user = result[entity] as { id?: unknown } | undefined
    if (user?.id == null) {
      return result
    }

    // Mint and persist a new refresh token for the session.
    const { secret, expiresIn } = getRefreshConfig(authConfig)
    const expiresAt = new Date(Date.now() + parseExpiresIn(expiresIn) * 1000)
    const refreshToken = await this.createAccessToken(
      { sid, typ: 'refresh' },
      {
        subject: String(user.id),
        expiresIn,
        algorithm: 'HS256'
      } as never,
      secret
    )

    const store = getRefreshTokenStore(this.app as Application)
    await store.issue({
      user_id: String(user.id),
      family_id: sid,
      token_hash: hashToken(refreshToken),
      expires_at: expiresAt,
      ...requestMeta(paramsWithSid)
    })

    return { ...result, refreshToken }
  }

  /**
   * Logout revokes the whole refresh-token family of the session the access token belongs
   * to. Access tokens issued before the refresh-token rollout (no `sid` claim) log out
   * without any server-side revocation — they simply expire.
   */
  override async remove(id: string | null, params?: AuthenticationParams) {
    const result = (await super.remove(id, params)) as Record<string, unknown> & {
      authentication?: { payload?: { sid?: string } }
    }
    const authConfig = this.configuration as Record<string, unknown>

    const sid = result?.authentication?.payload?.sid
    if (typeof sid === 'string') {
      const entity = (authConfig.entity as string) ?? 'user'
      const entityUser = result[entity] as { id?: unknown } | undefined
      if (entityUser?.id != null) {
        const store = getRefreshTokenStore(this.app as Application)
        await store.revokeFamily(sid, String(entityUser.id))
      }
    }

    return result
  }
}
