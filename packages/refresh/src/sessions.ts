import { BadRequest, NotAuthenticated, NotFound } from '@feathersjs/errors'
import type { Application } from '@feathersjs/feathers'

import { getRefreshTokenStore } from './strategy'
import type { RefreshTokenRecord } from './types'

/**
 * The client-facing view of one active session. Sensitive store fields
 * (`token_hash`, `revoked_at`, `replaced_by_id`, internal row `id`) are never exposed.
 * One row per session **family** — rotation keeps the same `id` (the `sid` claim).
 */
export interface SessionView {
  /** Session family id — the `sid` claim of the access token; stable across rotation. */
  id: string
  user_id: string
  user_agent: string | null
  ip_address: string | null
  /** Login time of the session (the original token of the family). */
  created_at: Date
  /** Expiry of the current refresh token of the session. */
  expires_at: Date
  /** `updated_at` of the active token — last rotation (or login) of this session. */
  last_used_at: Date
  /** `true` when this is the session the current request is authenticated with. */
  current: boolean
}

/**
 * Params accepted by {@link SessionService}. Works out of the box with the
 * `authenticate('jwt')` hook (which populates `params.authentication.payload` and
 * `params.user`); server-side calls may pass `{ user: { id } }` instead.
 */
export interface SessionParams {
  authentication?: {
    strategy?: string
    payload?: { sub?: string | number; sid?: string }
  }
  user?: { id?: string | number }
  query?: Record<string, unknown>
  [key: string]: unknown
}

export interface SessionsPluginOptions {
  /** Path to register the service under. Defaults to `'authentication/sessions'`. */
  path?: string
}

const DEFAULT_SESSIONS_PATH = 'authentication/sessions'

/**
 * Resolves the owning user id for a session-management request. Only two trusted
 * sources are accepted — the verified JWT payload (`sub`) or an explicit internal
 * `params.user` — never client-controlled query values. Everything is scoped to this
 * user: nobody can list or revoke another user's sessions.
 */
const resolveUserId = (params?: SessionParams): string => {
  const sub = params?.authentication?.payload?.sub
  if (sub != null && sub !== '') {
    return String(sub)
  }
  const id = params?.user?.id
  if (id != null && id !== '') {
    return String(id)
  }
  throw new NotAuthenticated('Authentication is required to manage sessions')
}

/**
 * Session listing and per-session revocation on top of any {@link RefreshTokenStore}:
 *
 * - `find(params)` — the active sessions of the authenticated user, one row per
 *   session family, newest first, with the request's own session flagged `current`.
 * - `remove(id, params)` — revokes one session family (its refresh token becomes
 *   unusable; the already-issued access token simply expires — like logout).
 * - `remove(null, params)` — revokes **all** sessions of the user ("log out everywhere").
 *
 * Results are always scoped to the authenticated user, and only hashes live in the
 * store, so no token material can ever leak through this service.
 */
export class SessionService {
  constructor(private readonly app: Application) {}

  private store() {
    return getRefreshTokenStore(this.app)
  }

  private toView(record: RefreshTokenRecord, currentSid?: string): SessionView {
    return {
      id: record.family_id,
      user_id: record.user_id,
      user_agent: record.user_agent,
      ip_address: record.ip_address,
      created_at: new Date(record.created_at),
      expires_at: new Date(record.expires_at),
      last_used_at: new Date(record.updated_at),
      current: currentSid != null && record.family_id === currentSid
    }
  }

  /**
   * Lists the active (non-revoked, non-expired) sessions of the authenticated user.
   * Query parameters are deliberately ignored — the list is always the caller's own.
   */
  async find(params?: SessionParams): Promise<SessionView[]> {
    const userId = resolveUserId(params)
    const currentSid = params?.authentication?.payload?.sid
    const records = await this.store().findActiveByUser(userId)
    return records.map((record) => this.toView(record, currentSid))
  }

  /**
   * Revokes one session family (`remove(id)`) or every session of the user
   * (`remove(null)`). Revoking an already-revoked or expired session is treated as
   * not found — nothing left to revoke.
   */
  async remove(id: string | null, params?: SessionParams): Promise<SessionView | { revoked: number }> {
    const userId = resolveUserId(params)
    const store = this.store()

    // "Log out everywhere" — revoke every active session of this user.
    if (id === null) {
      return { revoked: await store.revokeAllForUser(userId) }
    }

    if (typeof id !== 'string' || id.length === 0) {
      throw new BadRequest('A session id is required')
    }

    // Existence + ownership in one query scoped to the user: a session belonging to
    // somebody else is indistinguishable from a session that does not exist.
    const active = await store.findActiveByUser(userId)
    const target = active.find((record) => record.family_id === id)
    if (!target) {
      throw new NotFound(`Session '${id}' not found`)
    }

    const revokedCount = await store.revokeFamily(id, userId)
    if (revokedCount === 0) {
      // Lost a race with expiry or another revocation — same visible outcome.
      throw new NotFound(`Session '${id}' not found`)
    }

    return this.toView(target, params?.authentication?.payload?.sid)
  }
}

/**
 * Registers the {@link SessionService}:
 *
 * ```ts
 * import { refresh, sessions } from 'feathers-authentication-refresh'
 *
 * app.configure(refresh({ store }))
 * app.configure(sessions())                       // → /authentication/sessions
 * app.configure(sessions({ path: 'my-sessions' })) // custom path
 * ```
 *
 * Protect it with the JWT strategy on the client side:
 *
 * ```ts
 * app.service('authentication/sessions').hooks({
 *   before: { all: [authenticate('jwt')] }
 * })
 * ```
 */
export const sessions =
  (options: SessionsPluginOptions = {}) =>
  (app: Application) => {
    app.use(options.path ?? DEFAULT_SESSIONS_PATH, new SessionService(app))
  }
