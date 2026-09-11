import type { Application } from '@feathersjs/feathers'

import { getRefreshTokenStore } from './strategy'
import type { RefreshTokenStore } from './types'
import { parseExpiresIn } from './utils'

/**
 * Options for the expired-token purge job ({@link createPurgeJob} / {@link purgeJob}).
 */
export interface PurgeJobOptions {
  /**
   * The token store to purge. Defaults to the store registered on the app via
   * `refresh({ store })` (only available when used as an `app.configure` plugin).
   */
  store?: RefreshTokenStore
  /** How often the job runs, e.g. `'1h'`, `'15m'`. Defaults to `'24h'`. */
  interval?: string
  /**
   * Retention window: only tokens expired since longer than this are deleted, so
   * recently expired rows stay queryable for audits (reuse detection, forensics).
   * Defaults to `'0s'` — everything already expired is deleted.
   */
  olderThan?: string
  /** Runs one purge pass immediately when the job starts. Defaults to `false`. */
  runOnStart?: boolean
  /**
   * Called when a scheduled run fails so a transient store outage does not kill the
   * timer. Defaults to `console.error`.
   */
  onError?: (error: Error) => void
}

/** Control handle returned by {@link createPurgeJob}. */
export interface PurgeJobHandle {
  /**
   * Runs one purge pass immediately (outside the schedule) and resolves with the
   * number of rows deleted. Errors propagate to the caller.
   */
  run(): Promise<number>
  /** Stops the recurring schedule. `run()` stays usable for one-off manual purges. */
  stop(): void
  /** Whether the recurring schedule is currently active. */
  isRunning(): boolean
}

const DEFAULT_INTERVAL = '24h'
const DEFAULT_OLDER_THAN = '0s'

/**
 * Periodic cleanup of expired refresh tokens on top of any {@link RefreshTokenStore}'s
 * `purgeExpired` — without it, consumed/expired rows accumulate forever in SQL stores.
 *
 * Deletes **expired** tokens on a schedule — without it, consumed/expired rows
 * accumulate forever in SQL stores. Active and revoked-but-unexpired rows are never
 * touched; audit/forensic history is controlled by the `olderThan` retention window
 * (a revoked row that has also expired is deleted like any other expired row — by
 * then a replay is already dead because its whole family was revoked).
 *
 * ```ts
 * // Standalone
 * const job = createPurgeJob(store, { interval: '6h', olderThan: '30d' })
 * // — or as a Feathers plugin (store resolved from refresh({ store })):
 * app.configure(purgeJob({ interval: '6h', olderThan: '30d' }))
 * // — or in one step:
 * app.configure(refresh({ store, purge: { interval: '6h', olderThan: '30d' } }))
 * ```
 *
 * The underlying timer is `unref`'d so the job never keeps the process alive on its
 * own; call `stop()` on graceful shutdown (e.g. `app.get('refreshPurgeJob').stop()`).
 */
export const createPurgeJob = (store: RefreshTokenStore, options: PurgeJobOptions = {}): PurgeJobHandle => {
  const intervalMs = parseExpiresIn(options.interval ?? DEFAULT_INTERVAL) * 1000
  if (intervalMs <= 0) {
    throw new Error(`purge job interval must be positive, got '${options.interval}'`)
  }
  const olderThanMs = parseExpiresIn(options.olderThan ?? DEFAULT_OLDER_THAN) * 1000
  const onError =
    options.onError ??
    ((error: Error) => console.error('feathers-authentication-refresh: purge job failed', error))

  const purgeOnce = (): Promise<number> => store.purgeExpired(new Date(Date.now() - olderThanMs))

  let timer: NodeJS.Timeout | undefined

  const schedule = (): void => {
    timer = setInterval(() => {
      purgeOnce().catch(onError)
    }, intervalMs)
    // Never keep the process alive just for the purge schedule.
    timer.unref()
  }

  schedule()

  if (options.runOnStart) {
    purgeOnce().catch(onError)
  }

  return {
    run: purgeOnce,
    stop: () => {
      if (timer) {
        clearInterval(timer)
        timer = undefined
      }
    },
    isRunning: () => timer !== undefined
  }
}

const PURGE_JOB_KEY = 'refreshPurgeJob'
export { PURGE_JOB_KEY }

/**
 * Registers the expired-token purge job as a Feathers plugin. The store is resolved
 * from the app (the one passed to `refresh({ store })`), so this must be configured
 * **after** `refresh()` — or pass `options.store` explicitly.
 *
 * ```ts
 * import { refresh, purgeJob } from 'feathers-authentication-refresh'
 *
 * app.configure(refresh({ store }))
 * app.configure(purgeJob({ interval: '6h', olderThan: '30d' }))
 * ```
 *
 * The handle is available as `app.get('refreshPurgeJob')` — call `stop()` on
 * graceful shutdown.
 */
export const purgeJob =
  (options: PurgeJobOptions = {}) =>
  (app: Application) => {
    const store = options.store ?? getRefreshTokenStore(app)
    const job = createPurgeJob(store, options)
    app.set(PURGE_JOB_KEY, job)
  }
