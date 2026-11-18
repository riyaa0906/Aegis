import { createHash, randomUUID } from 'node:crypto'
import { Pool } from 'pg'
import type { ToolEffect } from '@aegis/shared-types'
import type { CallerIdentity } from './identity.js'
import type { ApprovalCache } from './cache.js'

export type ApprovalStatus =
  | 'pending'
  | 'approved'
  | 'executing'
  | 'completed'
  | 'rejected'
  | 'timeout'
  | 'escalated'
  | 'failed'

export type ApprovalRecord = {
  request_id: string
  idempotency_key: string
  agent_id: string
  role: string
  tool: string
  arguments: Record<string, unknown>
  effect: ToolEffect
  status: ApprovalStatus
  created_at: Date
  expires_at: Date
  decided_at: Date | null
  decided_by: string | null
  decision_reason: string | null
  /** Whether the caller has been told this request expired. */
  timeout_reported: boolean
  result: unknown
}

/** What the pipeline should do with a call whose policy decision is `approve`. */
export type ApprovalOutcome =
  | { kind: 'pending'; record: ApprovalRecord; created: boolean }
  | { kind: 'approved'; record: ApprovalRecord }
  | { kind: 'in_progress'; record: ApprovalRecord }
  | { kind: 'completed'; record: ApprovalRecord }
  | { kind: 'rejected'; record: ApprovalRecord }
  | { kind: 'timeout'; record: ApprovalRecord }

const SCHEMA = `
create table if not exists approvals (
  request_id uuid primary key,
  idempotency_key text not null,
  agent_id text not null,
  role text not null,
  tool text not null,
  arguments jsonb not null,
  effect text not null,
  status text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  decided_at timestamptz,
  decided_by text,
  decision_reason text,
  timeout_reported boolean not null default false,
  result jsonb
);
alter table approvals add column if not exists timeout_reported boolean not null default false;
create unique index if not exists approvals_open_action
  on approvals (idempotency_key)
  where status in ('pending', 'approved', 'executing');
`

/** Identifies the action, so a repeated request for the same action is the same request. */
export function idempotencyKey(
  identity: CallerIdentity,
  tool: string,
  args: Record<string, unknown>,
): string {
  const canonicalArgs = JSON.stringify(args, Object.keys(args).sort())
  return createHash('sha256')
    .update([identity.agent_id, identity.role, tool, canonicalArgs].join(' '))
    .digest('hex')
}

export type ApprovalStoreOptions = {
  timeoutMs: number
  cache?: ApprovalCache | null
}

export class ApprovalStore {
  constructor(
    private readonly pool: Pool,
    private readonly options: ApprovalStoreOptions,
  ) {}

  static async open(databaseUrl: string, options: ApprovalStoreOptions): Promise<ApprovalStore> {
    const pool = new Pool({ connectionString: databaseUrl })
    // Without this listener, an error on an idle pooled connection (e.g. Postgres going
    // away) is an unhandled 'error' event and crashes the process. Individual queries still
    // reject and are handled per-request, so this just keeps the gateway alive to fail closed.
    pool.on('error', (error) => {
      process.stderr.write(`approval store connection error: ${String(error)}\n`)
    })
    const store = new ApprovalStore(pool, options)
    await store.pool.query(SCHEMA)
    return store
  }

  async close(): Promise<void> {
    await this.pool.end()
  }

  private async byRequestId(requestId: string): Promise<ApprovalRecord | null> {
    const { rows } = await this.pool.query<ApprovalRecord>(
      'select * from approvals where request_id = $1',
      [requestId],
    )
    return rows[0] ?? null
  }

  private async openByKey(key: string): Promise<ApprovalRecord | null> {
    const cachedId = await this.options.cache?.get(key)
    if (cachedId) {
      const cached = await this.byRequestId(cachedId)
      if (cached && cached.idempotency_key === key) return cached
    }
    // Postgres is the authority; the cache only saves this lookup.
    const { rows } = await this.pool.query<ApprovalRecord>(
      `select * from approvals where idempotency_key = $1
       order by created_at desc limit 1`,
      [key],
    )
    return rows[0] ?? null
  }

  /**
   * Resolves the current state of an approval-gated call: it creates the request on first
   * sight and claims it for execution once a human has approved it.
   */
  async resolve(
    identity: CallerIdentity,
    tool: string,
    args: Record<string, unknown>,
    effect: ToolEffect,
  ): Promise<ApprovalOutcome> {
    const key = idempotencyKey(identity, tool, args)
    const existing = await this.openByKey(key)

    if (existing?.status === 'pending') {
      if (existing.expires_at.getTime() > Date.now()) {
        return { kind: 'pending', record: existing, created: false }
      }
      return { kind: 'timeout', record: await this.expire(existing.request_id) }
    }

    if (existing?.status === 'approved') {
      // Single-statement claim: concurrent resumes cannot both reach the tool.
      const { rows } = await this.pool.query<ApprovalRecord>(
        `update approvals set status = 'executing'
         where request_id = $1 and status = 'approved' returning *`,
        [existing.request_id],
      )
      const claimed = rows[0]
      if (claimed) return { kind: 'approved', record: claimed }
      const current = await this.byRequestId(existing.request_id)
      if (current?.status === 'completed') return { kind: 'completed', record: current }
      return { kind: 'in_progress', record: current ?? existing }
    }

    if (existing?.status === 'executing') return { kind: 'in_progress', record: existing }
    if (existing?.status === 'completed') return { kind: 'completed', record: existing }
    if (existing?.status === 'rejected') return { kind: 'rejected', record: existing }

    // A request the sweeper expired must still be reported, or a caller waiting on it would
    // wait forever. It is reported once; the call after that opens a fresh request.
    if (
      (existing?.status === 'timeout' || existing?.status === 'escalated') &&
      !existing.timeout_reported
    ) {
      return { kind: 'timeout', record: await this.markTimeoutReported(existing.request_id) }
    }

    // Anything else is closed and already reported; let the caller ask again.
    return {
      kind: 'pending',
      record: await this.create(key, identity, tool, args, effect),
      created: true,
    }
  }

  private async create(
    key: string,
    identity: CallerIdentity,
    tool: string,
    args: Record<string, unknown>,
    effect: ToolEffect,
  ): Promise<ApprovalRecord> {
    const requestId = randomUUID()
    const expiresAt = new Date(Date.now() + this.options.timeoutMs)
    const { rows } = await this.pool.query<ApprovalRecord>(
      `insert into approvals
         (request_id, idempotency_key, agent_id, role, tool, arguments, effect, status, expires_at)
       values ($1, $2, $3, $4, $5, $6, $7, 'pending', $8)
       on conflict (idempotency_key) where status in ('pending', 'approved', 'executing')
         do nothing
       returning *`,
      [
        requestId,
        key,
        identity.agent_id,
        identity.role,
        tool,
        JSON.stringify(args),
        effect,
        expiresAt,
      ],
    )
    // Lost a race with a concurrent identical request: adopt the winner.
    const record = rows[0] ?? (await this.openByKey(key))
    if (!record) throw new Error(`approval request for "${tool}" could not be recorded`)
    await this.options.cache?.set(key, record.request_id, this.options.timeoutMs)
    return record
  }

  async approve(requestId: string, decidedBy: string): Promise<ApprovalRecord | null> {
    const { rows } = await this.pool.query<ApprovalRecord>(
      `update approvals set status = 'approved', decided_at = now(), decided_by = $2
       where request_id = $1 and status = 'pending' and expires_at > now() returning *`,
      [requestId, decidedBy],
    )
    // Idempotent: approving again is a no-op that returns the record as it stands.
    return rows[0] ?? (await this.byRequestId(requestId))
  }

  async reject(
    requestId: string,
    decidedBy: string,
    reason?: string,
  ): Promise<ApprovalRecord | null> {
    const { rows } = await this.pool.query<ApprovalRecord>(
      `update approvals set status = 'rejected', decided_at = now(), decided_by = $2,
              decision_reason = $3
       where request_id = $1 and status = 'pending' returning *`,
      [requestId, decidedBy, reason ?? null],
    )
    const record = rows[0] ?? (await this.byRequestId(requestId))
    if (record) await this.options.cache?.drop(record.idempotency_key)
    return record
  }

  async markCompleted(requestId: string, result: unknown): Promise<void> {
    await this.pool.query(
      `update approvals set status = 'completed', result = $2 where request_id = $1`,
      [requestId, JSON.stringify(result)],
    )
  }

  async markFailed(requestId: string, reason: string): Promise<void> {
    await this.pool.query(
      `update approvals set status = 'failed', decision_reason = $2 where request_id = $1`,
      [requestId, reason],
    )
  }

  private async markTimeoutReported(requestId: string): Promise<ApprovalRecord> {
    const { rows } = await this.pool.query<ApprovalRecord>(
      `update approvals set timeout_reported = true where request_id = $1 returning *`,
      [requestId],
    )
    const record = rows[0]
    if (!record) throw new Error(`approval ${requestId} disappeared`)
    return record
  }

  private async expire(requestId: string): Promise<ApprovalRecord> {
    const { rows } = await this.pool.query<ApprovalRecord>(
      `update approvals set status = 'timeout', timeout_reported = true
       where request_id = $1 and status = 'pending' returning *`,
      [requestId],
    )
    const record = rows[0] ?? (await this.byRequestId(requestId))
    if (!record) throw new Error(`approval ${requestId} disappeared`)
    await this.options.cache?.drop(record.idempotency_key)
    return record
  }

  /** Times out every overdue request. Returns the ones a human should hear about. */
  async expireOverdue(): Promise<ApprovalRecord[]> {
    const { rows } = await this.pool.query<ApprovalRecord>(
      `update approvals set status = 'timeout'
       where status = 'pending' and expires_at <= now() returning *`,
    )
    for (const record of rows) await this.options.cache?.drop(record.idempotency_key)
    return rows
  }

  async markEscalated(requestId: string): Promise<void> {
    await this.pool.query(
      `update approvals set status = 'escalated' where request_id = $1 and status = 'timeout'`,
      [requestId],
    )
  }

  async listPending(): Promise<ApprovalRecord[]> {
    const { rows } = await this.pool.query<ApprovalRecord>(
      `select * from approvals where status = 'pending' order by created_at`,
    )
    return rows
  }

  async get(requestId: string): Promise<ApprovalRecord | null> {
    return this.byRequestId(requestId)
  }
}
