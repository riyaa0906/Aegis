import { Pool } from 'pg'
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApprovalStore, idempotencyKey, type ApprovalStore as Store } from '../src/approval.js'
import { connectCache, type ApprovalCache } from '../src/cache.js'
import { connectThroughGateway, errorCode } from './harness.js'

const DATABASE_URL =
  process.env.AEGIS_TEST_DATABASE_URL ?? 'postgres://aegis:aegis@127.0.0.1:5433/aegis'
const REDIS_URL = process.env.AEGIS_TEST_REDIS_URL ?? 'redis://127.0.0.1:6380'

const reachable = await (async () => {
  const pool = new Pool({ connectionString: DATABASE_URL, connectionTimeoutMillis: 2000 })
  try {
    await pool.query('select 1')
    return true
  } catch {
    process.stderr.write(`\nskipping approval tests: no Postgres at ${DATABASE_URL}\n`)
    return false
  } finally {
    await pool.end()
  }
})()

const support = { agent_id: 'agent-1', role: 'support_agent' }
const issueArgs = {
  repo: 'acme/billing-api',
  title: 'Retry backoff missing',
  body: 'Reported by a customer.',
}

const openStore = (timeoutMs: number, cache?: ApprovalCache) =>
  ApprovalStore.open(DATABASE_URL, { timeoutMs, cache })

describe.skipIf(!reachable)('approval store', () => {
  const pool = new Pool({ connectionString: DATABASE_URL })
  const stores: Store[] = []

  const store = async (timeoutMs = 60_000, cache?: ApprovalCache) => {
    const opened = await openStore(timeoutMs, cache)
    stores.push(opened)
    return opened
  }

  beforeEach(async () => {
    await pool.query('truncate table approvals').catch(() => {})
  })

  afterAll(async () => {
    await Promise.all(stores.map((opened) => opened.close()))
    await pool.end()
  })

  it('creates one pending request and reuses it for the same action', async () => {
    const approvals = await store()

    const first = await approvals.resolve(
      support,
      'github_create_issue',
      issueArgs,
      'WRITE_IRREVERSIBLE',
    )
    const second = await approvals.resolve(
      support,
      'github_create_issue',
      issueArgs,
      'WRITE_IRREVERSIBLE',
    )

    expect(first).toMatchObject({ kind: 'pending', created: true })
    expect(second).toMatchObject({ kind: 'pending', created: false })
    expect(second.record.request_id).toBe(first.record.request_id)
    expect((await pool.query('select count(*) from approvals')).rows[0].count).toBe('1')
  })

  it('creates one request when identical calls race', async () => {
    const approvals = await store()

    const outcomes = await Promise.all([
      approvals.resolve(support, 'github_create_issue', issueArgs, 'WRITE_IRREVERSIBLE'),
      approvals.resolve(support, 'github_create_issue', issueArgs, 'WRITE_IRREVERSIBLE'),
    ])

    expect(outcomes[0]?.record.request_id).toBe(outcomes[1]?.record.request_id)
    expect((await pool.query('select count(*) from approvals')).rows[0].count).toBe('1')
  })

  it('claims an approved request exactly once', async () => {
    const approvals = await store()
    const { record } = await approvals.resolve(
      support,
      'send_email',
      { to: 'a@b.example' },
      'WRITE_IRREVERSIBLE',
    )
    await approvals.approve(record.request_id, 'ops@aegis.example')

    const claimed = await approvals.resolve(
      support,
      'send_email',
      { to: 'a@b.example' },
      'WRITE_IRREVERSIBLE',
    )
    const second = await approvals.resolve(
      support,
      'send_email',
      { to: 'a@b.example' },
      'WRITE_IRREVERSIBLE',
    )

    expect(claimed.kind).toBe('approved')
    expect(claimed.record.decided_by).toBe('ops@aegis.example')
    expect(second.kind).toBe('in_progress')
  })

  it('replays a completed request instead of running it again', async () => {
    const approvals = await store()
    const { record } = await approvals.resolve(
      support,
      'send_email',
      { to: 'a@b.example' },
      'WRITE_IRREVERSIBLE',
    )
    await approvals.approve(record.request_id, 'ops@aegis.example')
    await approvals.resolve(support, 'send_email', { to: 'a@b.example' }, 'WRITE_IRREVERSIBLE')
    await approvals.markCompleted(record.request_id, { content: [{ type: 'text', text: 'sent' }] })

    const replay = await approvals.resolve(
      support,
      'send_email',
      { to: 'a@b.example' },
      'WRITE_IRREVERSIBLE',
    )

    expect(replay.kind).toBe('completed')
    expect(replay.record.result).toMatchObject({ content: [{ type: 'text', text: 'sent' }] })
  })

  it('treats repeated approvals as one decision', async () => {
    const approvals = await store()
    const { record } = await approvals.resolve(
      support,
      'github_create_issue',
      issueArgs,
      'WRITE_IRREVERSIBLE',
    )

    const first = await approvals.approve(record.request_id, 'ops@aegis.example')
    const second = await approvals.approve(record.request_id, 'someone-else@aegis.example')

    expect(first?.status).toBe('approved')
    expect(second?.status).toBe('approved')
    expect(second?.decided_by).toBe('ops@aegis.example')
  })

  it('keeps a rejected request rejected', async () => {
    const approvals = await store()
    const { record } = await approvals.resolve(
      support,
      'github_create_issue',
      issueArgs,
      'WRITE_IRREVERSIBLE',
    )
    await approvals.reject(record.request_id, 'ops@aegis.example', 'not needed')

    const outcome = await approvals.resolve(
      support,
      'github_create_issue',
      issueArgs,
      'WRITE_IRREVERSIBLE',
    )
    const lateApproval = await approvals.approve(record.request_id, 'ops@aegis.example')

    expect(outcome.kind).toBe('rejected')
    expect(outcome.record.decision_reason).toBe('not needed')
    expect(lateApproval?.status).toBe('rejected')
  })

  it('times out an overdue request, escalates it, and refuses to approve it', async () => {
    const approvals = await store(-1_000)
    const { record } = await approvals.resolve(
      support,
      'github_create_issue',
      issueArgs,
      'WRITE_IRREVERSIBLE',
    )

    const overdue = await approvals.expireOverdue()
    await approvals.markEscalated(record.request_id)
    const lateApproval = await approvals.approve(record.request_id, 'ops@aegis.example')
    const outcome = await approvals.resolve(
      support,
      'github_create_issue',
      issueArgs,
      'WRITE_IRREVERSIBLE',
    )

    expect(overdue.map((entry) => entry.request_id)).toEqual([record.request_id])
    expect((await approvals.get(record.request_id))?.status).toBe('escalated')
    expect(lateApproval?.status).toBe('escalated')
    // A caller waiting on the swept request is told once that it expired...
    expect(outcome).toMatchObject({ kind: 'timeout' })
    expect(outcome.record.request_id).toBe(record.request_id)

    // ...and only then may it open a fresh request.
    const retry = await approvals.resolve(
      support,
      'github_create_issue',
      issueArgs,
      'WRITE_IRREVERSIBLE',
    )
    expect(retry).toMatchObject({ kind: 'pending', created: true })
    expect(retry.record.request_id).not.toBe(record.request_id)
  })

  it('expires a pending request lazily when the caller comes back too late', async () => {
    const approvals = await store(-1_000)
    const { record } = await approvals.resolve(
      support,
      'send_email',
      { to: 'a@b.example' },
      'WRITE_IRREVERSIBLE',
    )

    // A second store instance stands in for a restarted process reading the same row.
    const restarted = await store(-1_000)
    const outcome = await restarted.resolve(
      support,
      'send_email',
      { to: 'a@b.example' },
      'WRITE_IRREVERSIBLE',
    )

    expect(outcome.kind).toBe('timeout')
    expect(outcome.record.request_id).toBe(record.request_id)
  })

  it('derives the same idempotency key regardless of argument order', () => {
    expect(idempotencyKey(support, 'send_email', { a: 1, b: 2 })).toBe(
      idempotencyKey(support, 'send_email', { b: 2, a: 1 }),
    )
    expect(idempotencyKey(support, 'send_email', { a: 1 })).not.toBe(
      idempotencyKey({ ...support, agent_id: 'other' }, 'send_email', { a: 1 }),
    )
  })

  it('resolves the same way with and without the Redis cache', async () => {
    const cache = await connectCache(REDIS_URL)
    const cached = await store(60_000, cache)

    const first = await cached.resolve(
      support,
      'github_create_issue',
      issueArgs,
      'WRITE_IRREVERSIBLE',
    )
    const second = await cached.resolve(
      support,
      'github_create_issue',
      issueArgs,
      'WRITE_IRREVERSIBLE',
    )
    // Postgres is the authority: a store with no cache sees exactly the same request.
    const uncached = await store()
    const third = await uncached.resolve(
      support,
      'github_create_issue',
      issueArgs,
      'WRITE_IRREVERSIBLE',
    )

    expect(second.record.request_id).toBe(first.record.request_id)
    expect(third.record.request_id).toBe(first.record.request_id)
    await cache.close()
  })
})

describe.skipIf(!reachable)('approval flow through the gateway', () => {
  const pool = new Pool({ connectionString: DATABASE_URL })
  const stores: Store[] = []

  const store = async (timeoutMs = 60_000) => {
    const opened = await openStore(timeoutMs)
    stores.push(opened)
    return opened
  }

  beforeEach(async () => {
    await pool.query('truncate table approvals').catch(() => {})
  })

  afterAll(async () => {
    await Promise.all(stores.map((opened) => opened.close()))
    await pool.end()
  })

  it('requests approval, notifies once, and does not call the MCP server', async () => {
    const approvals = await store()
    const notify = vi.fn()
    const { call, upstreamCall } = await connectThroughGateway({
      role: 'support_agent',
      approvals,
      notify,
    })

    const first = await call('github_create_issue', issueArgs)
    const second = await call('github_create_issue', issueArgs)

    expect(errorCode(first)).toBe('APPROVAL_REQUIRED')
    expect(errorCode(second)).toBe('APPROVAL_REQUIRED')
    expect(first._meta?.['aegis/request_id']).toBe(second._meta?.['aegis/request_id'])
    expect(notify).toHaveBeenCalledTimes(1)
    expect(notify.mock.calls[0]?.[0]).toBe('approval_requested')
    expect(upstreamCall).not.toHaveBeenCalled()
    expect(await approvals.listPending()).toHaveLength(1)
  })

  it('executes exactly once after approval, then replays the stored result', async () => {
    const approvals = await store()
    const { call, upstreamCall } = await connectThroughGateway({ role: 'support_agent', approvals })

    const held = await call('github_create_issue', issueArgs)
    await approvals.approve(String(held._meta?.['aegis/request_id']), 'ops@aegis.example')

    const executed = await call('github_create_issue', issueArgs)
    const repeated = await call('github_create_issue', issueArgs)

    expect(executed.isError).toBeFalsy()
    expect(executed.structuredContent).toMatchObject({ repo: 'acme/billing-api' })
    expect(executed._meta?.['aegis/approved_by']).toBe('ops@aegis.example')
    expect(upstreamCall).toHaveBeenCalledTimes(1)

    expect(repeated._meta?.['aegis/replayed']).toBe(true)
    expect(repeated.structuredContent).toEqual(executed.structuredContent)
    expect(upstreamCall).toHaveBeenCalledTimes(1)

    const record = await approvals.get(String(held._meta?.['aegis/request_id']))
    expect(record?.status).toBe('completed')
  })

  it('never executes a rejected request', async () => {
    const approvals = await store()
    const { call, upstreamCall } = await connectThroughGateway({ role: 'support_agent', approvals })

    const held = await call('github_create_issue', issueArgs)
    await approvals.reject(String(held._meta?.['aegis/request_id']), 'ops@aegis.example', 'no')

    const afterRejection = await call('github_create_issue', issueArgs)

    expect(errorCode(afterRejection)).toBe('APPROVAL_REJECTED')
    expect(upstreamCall).not.toHaveBeenCalled()
  })

  it('never executes an expired request', async () => {
    const approvals = await store(-1_000)
    const { call, upstreamCall } = await connectThroughGateway({ role: 'support_agent', approvals })

    const held = await call('github_create_issue', issueArgs)
    const afterExpiry = await call('github_create_issue', issueArgs)

    expect(errorCode(held)).toBe('APPROVAL_REQUIRED')
    expect(errorCode(afterExpiry)).toBe('APPROVAL_TIMEOUT')
    expect(upstreamCall).not.toHaveBeenCalled()
  })

  it('resumes an approval created before the gateway restarted', async () => {
    const beforeRestart = await store()
    const held = await (
      await connectThroughGateway({ role: 'support_agent', approvals: beforeRestart })
    ).call('github_create_issue', issueArgs)

    await beforeRestart.approve(String(held._meta?.['aegis/request_id']), 'ops@aegis.example')
    await beforeRestart.close()
    stores.splice(stores.indexOf(beforeRestart), 1)

    // A brand new store and gateway: everything they know comes from Postgres.
    const afterRestart = await store()
    const restarted = await connectThroughGateway({
      role: 'support_agent',
      approvals: afterRestart,
    })
    const executed = await restarted.call('github_create_issue', issueArgs)

    expect(executed.isError).toBeFalsy()
    expect(executed._meta?.['aegis/request_id']).toBe(held._meta?.['aegis/request_id'])
    expect(restarted.upstreamCall).toHaveBeenCalledTimes(1)
  })
})
