import { Pool } from 'pg'
import {
  InMemorySpanExporter,
  NodeTracerProvider,
  SimpleSpanProcessor,
  type ReadableSpan,
} from '@opentelemetry/sdk-trace-node'
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApprovalStore } from '../src/approval.js'
import type { Classifier } from '../src/screening.js'
import { connectThroughGateway } from './harness.js'

const DATABASE_URL =
  process.env.AEGIS_TEST_DATABASE_URL ?? 'postgres://aegis:aegis@127.0.0.1:5433/aegis'

const exporter = new InMemorySpanExporter()
const provider = new NodeTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] })
provider.register()

const auditLines: string[] = []
vi.spyOn(console, 'error').mockImplementation((line: unknown) => {
  auditLines.push(String(line).trim())
})

const stubClassifier: Classifier = (text) =>
  Promise.resolve(text.includes('Ignore all previous instructions') ? 0.97 : 0.02)

const BENIGN_ISSUE = { repo: 'acme/billing-api', issue_number: 142 }
const POISONED_ISSUE = { repo: 'acme/billing-api', issue_number: 144 }

const spanNames = () => exporter.getFinishedSpans().map((span) => span.name)
const spanNamed = (name: string): ReadableSpan => {
  const span = exporter.getFinishedSpans().find((candidate) => candidate.name === name)
  if (!span) throw new Error(`no span named ${name} in ${spanNames().join(', ')}`)
  return span
}
const auditEvents = () =>
  auditLines
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line) as Record<string, unknown>)
const auditEvent = (event: string) => auditEvents().find((entry) => entry.event === event)

beforeEach(() => {
  exporter.reset()
  auditLines.length = 0
})

afterAll(async () => {
  await provider.shutdown()
})

describe('tracing a tool call', () => {
  it('covers every stage of an executed call', async () => {
    const { call } = await connectThroughGateway({
      role: 'support_agent',
      classifier: stubClassifier,
    })

    await call('get_github_issue', BENIGN_ISSUE)

    expect(spanNames()).toEqual(
      expect.arrayContaining([
        'aegis.authorize',
        'aegis.validate_arguments',
        'aegis.execute',
        'aegis.screen_output',
        'aegis.tool_call',
      ]),
    )

    const root = spanNamed('aegis.tool_call')
    expect(root.attributes).toMatchObject({
      'aegis.tool': 'get_github_issue',
      'aegis.agent_id': 'agent-1',
      'aegis.role': 'support_agent',
      'aegis.effect': 'READ_ONLY',
      'aegis.execution_status': 'completed',
    })
    expect(root.attributes['aegis.request_id']).toEqual(expect.any(String))
    expect(root.attributes['aegis.latency_ms']).toBeGreaterThanOrEqual(0)

    expect(spanNamed('aegis.authorize').attributes).toMatchObject({
      'aegis.policy_decision': 'auto',
      'aegis.approval_required': false,
      'aegis.effect': 'READ_ONLY',
    })
    expect(spanNamed('aegis.validate_arguments').attributes).toMatchObject({
      'aegis.arguments_valid': true,
      'aegis.argument_names': ['issue_number', 'repo'],
    })
    expect(spanNamed('aegis.screen_output').attributes).toMatchObject({
      'aegis.screening_status': 'clean',
      'aegis.screening_action': 'allow',
      'aegis.injection_score': 0.02,
    })
  })

  it('keeps every stage of one call in a single trace', async () => {
    const { call } = await connectThroughGateway({
      role: 'support_agent',
      classifier: stubClassifier,
    })

    await call('get_github_issue', BENIGN_ISSUE)

    const traceIds = new Set(exporter.getFinishedSpans().map((span) => span.spanContext().traceId))
    expect(traceIds.size).toBe(1)
  })

  it('records a refusal without reaching the execute stage', async () => {
    const { call } = await connectThroughGateway({
      role: 'support_agent',
      classifier: stubClassifier,
    })

    await call('send_email', { recipient: 'a@b.example', subject: 'x', body: 'y' })

    expect(spanNames()).not.toContain('aegis.execute')
    expect(spanNamed('aegis.authorize').attributes['aegis.policy_decision']).toBe('deny')
    expect(spanNamed('aegis.tool_call').attributes).toMatchObject({
      'aegis.execution_status': 'refused',
      'aegis.error_code': 'TOOL_NOT_ALLOWED',
    })
  })

  it('records an invalid call at the validation stage', async () => {
    const { call } = await connectThroughGateway({
      role: 'support_agent',
      classifier: stubClassifier,
    })

    await call('get_github_issue', { repo: 'acme/billing-api', issue_number: '142' })

    expect(spanNamed('aegis.validate_arguments').attributes['aegis.arguments_valid']).toBe(false)
    expect(spanNames()).not.toContain('aegis.execute')
    expect(spanNamed('aegis.tool_call').attributes['aegis.error_code']).toBe('INVALID_ARGUMENTS')
  })

  it('records the injection score that withheld output', async () => {
    const { call } = await connectThroughGateway({
      role: 'support_agent',
      classifier: stubClassifier,
    })

    await call('get_github_issue', POISONED_ISSUE)

    expect(spanNamed('aegis.screen_output').attributes).toMatchObject({
      'aegis.screening_status': 'high_risk',
      'aegis.screening_action': 'block',
      'aegis.injection_score': 0.97,
    })
    expect(spanNamed('aegis.tool_call').attributes['aegis.error_code']).toBe(
      'OUTPUT_SECURITY_BLOCKED',
    )
  })
})

describe('audit log', () => {
  it('records the decision for an executed call', async () => {
    const { call } = await connectThroughGateway({
      role: 'support_agent',
      classifier: stubClassifier,
    })

    await call('get_github_issue', BENIGN_ISSUE)

    expect(auditEvent('tool_requested')).toMatchObject({
      tool: 'get_github_issue',
      agent_id: 'agent-1',
      role: 'support_agent',
      argument_names: ['issue_number', 'repo'],
    })
    expect(auditEvent('authorization')).toMatchObject({
      policy_decision: 'auto',
      effect: 'READ_ONLY',
    })
    const decision = auditEvent('decision')
    expect(decision).toMatchObject({
      tool: 'get_github_issue',
      execution_status: 'completed',
      effect: 'READ_ONLY',
      injection_score: 0.02,
    })
    expect(decision?.latency_ms).toEqual(expect.any(Number))
    expect(decision?.trace_id).toBe(spanNamed('aegis.tool_call').spanContext().traceId)
  })

  it('never writes argument values or tool output', async () => {
    const { call } = await connectThroughGateway({
      role: 'support_agent',
      classifier: stubClassifier,
    })

    await call('get_github_issue', BENIGN_ISSUE)
    await call('get_github_issue', POISONED_ISSUE)
    const log = auditLines.join('\n')

    // Argument values...
    expect(log).not.toContain('acme/billing-api')
    // ...benign tool output...
    expect(log).not.toContain('Webhook retries stop after the first 5xx')
    // ...and above all, the attacker's payload.
    expect(log).not.toContain('attacker@evil.example')
    expect(log).not.toContain('Ignore all previous instructions')
    // The screening verdict is still recorded.
    expect(auditEvent('output_screening')).toMatchObject({
      screening_status: 'high_risk',
      screening_action: 'block',
      injection_score: 0.97,
    })
  })

  it('records why a call was refused, without the offending value', async () => {
    const { call } = await connectThroughGateway({
      role: 'support_agent',
      classifier: stubClassifier,
    })

    await call('get_payment_status', { transaction_id: 'txn_3ab21f9c', internal_override: true })

    expect(auditEvent('validation_failed')).toMatchObject({
      tool: 'get_payment_status',
      reason: 'undeclared argument(s): internal_override',
    })
    expect(auditLines.join('\n')).not.toContain('txn_3ab21f9c')
  })
})

const postgresReachable = await (async () => {
  const pool = new Pool({ connectionString: DATABASE_URL, connectionTimeoutMillis: 2000 })
  try {
    await pool.query('select 1')
    return true
  } catch {
    return false
  } finally {
    await pool.end()
  }
})()

describe.skipIf(!postgresReachable)('tracing the approval gate', () => {
  it('records the approval request without executing the tool', async () => {
    const approvals = await ApprovalStore.open(DATABASE_URL, { timeoutMs: 60_000 })
    const pool = new Pool({ connectionString: DATABASE_URL })
    await pool.query('truncate table approvals')

    const { call } = await connectThroughGateway({
      role: 'support_agent',
      classifier: stubClassifier,
      approvals,
    })
    await call('github_create_issue', {
      repo: 'acme/web',
      title: 'Session expiry',
      body: 'Drafts are lost.',
    })

    expect(spanNamed('aegis.authorize').attributes).toMatchObject({
      'aegis.policy_decision': 'approve',
      'aegis.approval_required': true,
    })
    expect(spanNamed('aegis.approval').attributes).toMatchObject({
      'aegis.approval_outcome': 'pending',
      'aegis.approval_status': 'pending',
    })
    expect(spanNames()).not.toContain('aegis.execute')
    expect(auditEvent('approval')).toMatchObject({
      approval_outcome: 'pending',
      approval_status: 'pending',
    })
    expect(auditEvent('decision')).toMatchObject({ error_code: 'APPROVAL_REQUIRED' })

    await approvals.close()
    await pool.end()
  })
})
