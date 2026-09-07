import { createHash } from 'node:crypto'
import { isIP } from 'node:net'
import type { RefreshRequestMeta } from './types'

const EXPIRY_MULTIPLIERS = { s: 1, m: 60, h: 3600, d: 86400 } as const

/** Parses a duration string to seconds (`15m` -> 900, `7d` -> 604800). */
export const parseExpiresIn = (value: string): number => {
  const match = /^(\d+)([smhd])$/.exec(value.trim())
  if (!match) {
    throw new Error(`Invalid duration format: '${value}' (expected e.g. '15m', '7d')`)
  }
  return Number.parseInt(match[1], 10) * EXPIRY_MULTIPLIERS[match[2] as keyof typeof EXPIRY_MULTIPLIERS]
}

/** SHA-256 hash of a raw token, hex encoded. This is the only form ever persisted. */
export const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex')

/** Extracts `user_agent` and `ip_address` metadata from a request's headers. */
export const requestMeta = (params: {
  headers?: Record<string, string | string[] | undefined>
}): RefreshRequestMeta => {
  const headers = params.headers ?? {}
  const userAgent = headers['user-agent']
  const forwardedFor = headers['x-forwarded-for']
  let ip: string | null = null
  if (typeof forwardedFor === 'string' && forwardedFor.length > 0) {
    const candidate = forwardedFor.split(',')[0].trim()
    ip = isIP(candidate) !== 0 ? candidate : null
  }
  return {
    user_agent: typeof userAgent === 'string' && userAgent.length > 0 ? userAgent.slice(0, 1024) : null,
    ip_address: ip
  }
}
