import type { Context, Next } from 'koa'
import type { Application } from '@feathersjs/feathers'

import type { RefreshConfig, RefreshCookieConfig } from './types'
import { getRefreshConfig } from './strategy'
import { parseExpiresIn } from './utils'

export type { RefreshCookieConfig } from './types'

/** The fully-resolved, safe cookie attributes handed to `ctx.cookies.set`. */
export interface ResolvedCookieConfig {
  name: string
  secure: boolean
  sameSite: 'lax' | 'strict' | 'none'
  path: string
  domain?: string
  /** Cookie lifetime in milliseconds, derived from `refresh.expiresIn`. */
  maxAge: number
  /** Always `true` — the whole point of this feature. */
  httpOnly: true
}

const DEFAULT_COOKIE_PATH = '/authentication'

/**
 * Resolves `authentication.refresh.cookie` into concrete cookie attributes.
 * Returns `null` when the section is absent (cookie support disabled).
 * Never throws: an incomplete `authentication.refresh` section disables cookies.
 */
export const resolveCookieConfig = (authConfig: Record<string, unknown>): ResolvedCookieConfig | null => {
  try {
    const refresh = authConfig.refresh as Partial<RefreshConfig> | undefined
    if (!refresh?.cookie) {
      return null
    }
    const cookie = refresh.cookie as RefreshCookieConfig
    const { expiresIn } = getRefreshConfig(authConfig)
    return {
      name: cookie.name ?? 'refreshToken',
      secure: cookie.secure ?? true,
      sameSite: cookie.sameSite ?? 'lax',
      path: cookie.path ?? DEFAULT_COOKIE_PATH,
      ...(cookie.domain ? { domain: cookie.domain } : {}),
      maxAge: parseExpiresIn(expiresIn) * 1000,
      httpOnly: true
    }
  } catch {
    return null
  }
}

const cookieAttributes = (config: ResolvedCookieConfig) => ({
  httpOnly: true,
  secure: config.secure,
  sameSite: config.sameSite,
  path: config.path,
  ...(config.domain ? { domain: config.domain } : {}),
  maxAge: config.maxAge,
  overwrite: true
})

/** `ctx.path` with trailing slashes normalized, so `/authentication/` matches too. */
const matchesAuthPath = (ctx: Context, path: string) => ctx.path.replace(/\/+$/, '') === path

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

/**
 * Koa middleware that transparently moves the refresh token into an HTTP-only cookie.
 *
 * - Response phase: any successful `POST /authentication` whose body carries a
 *   `refreshToken` (login or rotation) gets the token moved into the cookie and
 *   stripped from the JSON response.
 * - `httpOnly: true` is forced; `maxAge` is derived from `refresh.expiresIn`.
 *
 * MANDATORY position: after `bodyParser()` and before `rest()`:
 *
 * ```ts
 * app.use(errorHandler())
 * app.use(bodyParser())
 * app.use(refreshCookie(app))
 * app.configure(rest())
 * ```
 *
 * Inert (pass-through) when `authentication.refresh.cookie` is not configured,
 * so it is safe to always mount.
 */
export const refreshCookie = (app: Application) => {
  const resolveForRequest = (): ResolvedCookieConfig | null => {
    try {
      const authService = app.service('authentication') as unknown as {
        configuration?: Record<string, unknown>
      }
      return authService?.configuration ? resolveCookieConfig(authService.configuration) : null
    } catch {
      // The authentication service is not registered — treat as disabled.
      return null
    }
  }

  return async (ctx: Context, next: Next): Promise<void> => {
    const config = resolveForRequest()

    // Request phase: on a token-less refresh request, fall back to the cookie.
    // An explicit body refreshToken always wins (`body ?? cookie`) so non-cookie
    // clients keep working unchanged.
    if (config && ctx.method === 'POST' && matchesAuthPath(ctx, config.path)) {
      // `body` is attached at runtime by the body parser — not in Koa's Request type.
      const requestBody = (ctx.request as unknown as { body?: unknown }).body
      if (isPlainObject(requestBody) && requestBody.strategy === 'refresh' && !requestBody.refreshToken) {
        const token = ctx.cookies.get(config.name)
        if (token) {
          requestBody.refreshToken = token
        }
      }
    }

    await next()

    if (!config) {
      return
    }

    if (ctx.method === 'DELETE' && matchesAuthPath(ctx, config.path)) {
      // Koa/cookies idiom: `set(name, null, opts)` emits an expired cookie. Same
      // path/domain attributes so the browser replaces the existing one.
      // Errors from `next()` skip this — a failed logout never touches the cookie.
      ctx.cookies.set(config.name, null, cookieAttributes(config))
      return
    }

    if (
      ctx.method === 'POST' &&
      matchesAuthPath(ctx, config.path) &&
      isPlainObject(ctx.body) &&
      typeof ctx.body.refreshToken === 'string' &&
      ctx.body.refreshToken.length > 0
    ) {
      const { refreshToken, ...rest } = ctx.body
      ctx.cookies.set(config.name, refreshToken, cookieAttributes(config))
      ctx.body = rest
    }
  }
}
