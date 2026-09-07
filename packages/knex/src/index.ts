import type { Knex } from 'knex'

export * from './store'

/**
 * Creates the `refresh_tokens` table (or the name given via `tableName`).
 *
 * Run it in your migration setup, e.g. in a Knex migration file:
 *
 * ```ts
 * import { createRefreshTokensTable } from 'feathers-authentication-refresh-knex'
 *
 * export async function up(knex: Knex) {
 *   await createRefreshTokensTable(knex)
 * }
 *
 * export async function down(knex: Knex) {
 *   await dropRefreshTokensTable(knex)
 * }
 * ```
 */
export const createRefreshTokensTable = (knex: Knex, tableName = 'refresh_tokens') =>
  knex.schema.createTable(tableName, (table) => {
    table.uuid('id').primary()
    table.uuid('family_id').notNullable()
    // `user_id` is a plain string to support any user id scheme (uuid, integer, ...)
    table.string('user_id').notNullable()
    table.string('token_hash', 64).notNullable().unique()
    table.dateTime('expires_at').notNullable()
    table.string('user_agent', 1024).nullable()
    table.string('ip_address', 45).nullable()
    table.dateTime('revoked_at').nullable()
    table.uuid('replaced_by_id').nullable()
    table.dateTime('created_at').notNullable()
    table.dateTime('updated_at').notNullable()

    table.index(['user_id'])
    table.index(['family_id'])
  })

/** Drops the refresh tokens table. */
export const dropRefreshTokensTable = (knex: Knex, tableName = 'refresh_tokens') =>
  knex.schema.dropTableIfExists(tableName)
