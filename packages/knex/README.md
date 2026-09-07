# feathers-authentication-refresh-knex

Knex adapter for [`feathers-authentication-refresh`](../refresh): a SQL-backed
`RefreshTokenStore` with transactional, row-locked rotation. Works with PostgreSQL,
SQLite, MySQL and any other Knex-supported dialect.

## Install

```bash
npm install feathers-authentication-refresh-knex knex
```

## Migration

```ts
import type { Knex } from 'knex'
import { createRefreshTokensTable, dropRefreshTokensTable } from 'feathers-authentication-refresh-knex'

export async function up(knex: Knex) {
  await createRefreshTokensTable(knex) // pass a custom name as 2nd arg if needed
}

export async function down(knex: Knex) {
  await dropRefreshTokensTable(knex)
}
```

## Usage

```ts
import { refresh } from 'feathers-authentication-refresh'
import { KnexRefreshTokenStore } from 'feathers-authentication-refresh-knex'

const database = knex({ client: 'pg', connection: process.env.DATABASE_URL })

app.configure(refresh({ store: new KnexRefreshTokenStore(database) }))
// custom table name:
app.configure(refresh({ store: new KnexRefreshTokenStore(database, { tableName: 'my_sessions' }) }))
```

## Notes

- Only `SHA-256(token)` hashes are persisted (hashing happens in the core package).
- Rotation runs in a transaction with `SELECT ... FOR UPDATE` on dialects that support it
  (PostgreSQL, MySQL, ...); SQLite serializes writes which gives an equivalent guarantee
  for a single server.
- `user_id` is stored as a plain string to support any user id scheme (uuid, integer, ...).

## License

MIT
