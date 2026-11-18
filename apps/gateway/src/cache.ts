import { createClient } from 'redis'

/**
 * Fast lookup from an action's idempotency key to its open approval request.
 * Postgres remains the source of truth: every hit is re-read from the database, and the
 * gateway stays correct (only slower) when Redis is absent, stale or failing.
 */
export type ApprovalCache = {
  get(key: string): Promise<string | null>
  set(key: string, requestId: string, ttlMs: number): Promise<void>
  drop(key: string): Promise<void>
  close(): Promise<void>
}

export async function connectCache(url: string): Promise<ApprovalCache> {
  const client = createClient({
    url,
    // Give up reconnecting after a few tries so a persistently-down Redis makes operations
    // fail fast (and be swallowed) instead of queueing; without this, connect() would retry
    // forever and block gateway startup.
    disableOfflineQueue: true,
    socket: {
      connectTimeout: 2_000,
      reconnectStrategy: (retries) =>
        retries >= 5 ? new Error('redis unavailable') : Math.min(retries * 100, 500),
    },
  })
  // The error event is expected while Redis is unreachable; log once per failure, non-fatal.
  client.on('error', (error: unknown) => {
    process.stderr.write(`approval cache error: ${String(error)}\n`)
  })
  await client.connect()

  const cacheKey = (key: string) => `aegis:approval:${key}`
  const swallow = async <T>(operation: Promise<T>, fallback: T): Promise<T> => {
    try {
      return await operation
    } catch {
      return fallback
    }
  }

  return {
    get: (key) => swallow(client.get(cacheKey(key)), null),
    set: async (key, requestId, ttlMs) => {
      await swallow(client.set(cacheKey(key), requestId, { PX: ttlMs }), null)
    },
    drop: async (key) => {
      await swallow(client.del(cacheKey(key)), 0)
    },
    close: async () => {
      await client.close()
    },
  }
}
