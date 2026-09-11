# feathers-authentication-refresh-mongodb

MongoDB adapter for [`feathers-authentication-refresh`](../refresh): a
`RefreshTokenStore` with atomic, transaction-free rotation, built on the official
`mongodb` driver.

## Install

```bash
npm install feathers-authentication-refresh-mongodb mongodb
```

## Indexes

Create the indexes the store relies on during your setup or migration step:

```ts
import { MongoClient } from 'mongodb'
import { createRefreshTokensIndexes } from 'feathers-authentication-refresh-mongodb'

const client = new MongoClient(process.env.MONGODB_URL)
await client.connect()
await createRefreshTokensIndexes(client.db()) // pass a custom collection name as 2nd arg
```

No TTL index is created on purpose: expired tokens must be kept for the
audit/reuse-detection window and are removed by the core package's purge job
(`purgeExpired`).

## Usage

```ts
import { MongoClient } from 'mongodb'
import { refresh } from 'feathers-authentication-refresh'
import { MongoRefreshTokenStore } from 'feathers-authentication-refresh-mongodb'

const client = new MongoClient(process.env.MONGODB_URL)
await client.connect()

app.configure(refresh({ store: new MongoRefreshTokenStore(client.db()) }))
// custom collection name:
app.configure(refresh({ store: new MongoRefreshTokenStore(client.db(), { collectionName: 'my_sessions' }) }))
```

## Notes

- Only `SHA-256(token)` hashes are persisted (hashing happens in the core package).
- Rotation is atomic **without multi-document transactions**: the consumed document is
  claimed with a conditional `updateOne({ _id, revoked_at: null })`. Concurrent rotations
  of the same token race on that single document — exactly one wins, the loser is
  reported as a reuse and the caller revokes the whole session family. This works on
  standalone servers as well as replica sets.
- `_id` holds a client-generated UUID (surfaced as `id`) so records can be inserted and
  linked (`replaced_by_id`) without server round-trips.
- `user_id` is stored as a plain string to support any user id scheme (uuid, integer, ...).

## License

MIT
