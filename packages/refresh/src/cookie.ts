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
export const resolveCookieConfig = (
  authConfig: Record<string, unknown>
): ResolvedCookieConfig | null => {
  try {
    const refresh = authConfig.refresh as Partial<RefreshConfig> | undefined
    if (!refresh?.cookie) {
      return null
    }
    const cookie = (refresh.cookie ?? {}) as RefreshCookieConfig
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
