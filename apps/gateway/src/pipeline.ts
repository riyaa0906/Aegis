import { randomUUID } from 'node:crypto'
import { SpanStatusCode, type Span } from '@opentelemetry/api'
import type { Client } from '@modelcontextprotocol/sdk/client/index.js'
import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js'
import type { AegisErrorCode, ToolEffect } from '@aegis/shared-types'
import type { ApprovalRecord, ApprovalStore } from './approval.js'
import type { CallerIdentity } from './identity.js'
import type { Notifier } from './notify.js'
import { argumentNames, audit } from './audit.js'
import { authorize, screeningConfig, type Policy } from './policy.js'
import { applyProvenance, textOf } from './provenance.js'
import { screenOutput, type Classifier } from './screening.js'
import { tracer, withSpan } from './telemetry.js'
import { validateArguments } from './validation.js'

export type GatewayContext = {
  upstream: Client
  policy: Policy
  identity: CallerIdentity | null
  approvals?: ApprovalStore | null
  notify?: Notifier
  classifier?: Classifier | null
}

// Upstream calls get an explicit deadline rather than relying on the SDK default, so a hung
// MCP server cannot hold a gateway request open indefinitely.
const CALL_TIMEOUT_MS = Number(process.env.AEGIS_MCP_CALL_TIMEOUT_MS ?? 30_000)
const LIST_TIMEOUT_MS = Number(process.env.AEGIS_MCP_LIST_TIMEOUT_MS ?? 10_000)

function refuse(
  code: AegisErrorCode,
  message: string,
  meta: Record<string, unknown> = {},
): CallToolResult {
  return {
    isError: true,
    content: [{ type: 'text', text: `${code}: ${message}` }],
    _meta: { 'aegis/error_code': code, ...meta },
  }
}

const upstreamToolCache = new WeakMap<Client, Tool[]>()

/** The tool list rarely changes; it is fetched once per upstream connection. */
async function upstreamTools(upstream: Client): Promise<Tool[]> {
  const cached = upstreamToolCache.get(upstream)
  if (cached) return cached
  const { tools } = await upstream.listTools(undefined, { timeout: LIST_TIMEOUT_MS })
  upstreamToolCache.set(upstream, tools)
  return tools
}

/** Least privilege: a caller only sees the tools it is allowed to request. */
export async function listAllowedTools(ctx: GatewayContext): Promise<Tool[]> {
  const tools = await upstreamTools(ctx.upstream)
  return tools.filter((tool) => authorize(ctx.policy, ctx.identity, tool.name).decision !== 'deny')
}

/**
 * Calls the MCP server with a deadline. A READ_ONLY tool is retried once on a transport
 * failure because it has no side effect; a WRITE tool is never retried, so a timed-out
 * write is not silently duplicated.
 */
async function callUpstream(
  upstream: Client,
  name: string,
  args: Record<string, unknown>,
  effect: ToolEffect,
): Promise<CallToolResult> {
  const attempt = () =>
    upstream.callTool({ name, arguments: args }, undefined, {
      timeout: CALL_TIMEOUT_MS,
    }) as Promise<CallToolResult>
  try {
    return await attempt()
  } catch (error) {
    if (effect !== 'READ_ONLY') throw error
    return attempt()
  }
}

/**
 * Runs the tool, then screens and fences what it returned. Tool output never reaches the
 * agent as plain content: it comes back as untrusted data with its provenance attached.
 */
async function execute(
  ctx: GatewayContext,
  name: string,
  args: Record<string, unknown>,
  effect: ToolEffect,
  requestId: string,
  meta: Record<string, unknown> = {},
): Promise<CallToolResult> {
  const result = await withSpan(
    'aegis.execute',
    { 'aegis.tool': name, 'aegis.effect': effect },
    async (span) => {
      const executed = await callUpstream(ctx.upstream, name, args, effect)
      span.setAttribute('aegis.upstream_error', executed.isError === true)
      return executed
    },
  )

  const screening = await withSpan('aegis.screen_output', { 'aegis.tool': name }, async (span) => {
    const verdict = await screenOutput(textOf(result), ctx.classifier, screeningConfig(ctx.policy))
    span.setAttributes({
      'aegis.screening_status': verdict.status,
      'aegis.screening_action': verdict.action,
      ...(verdict.score === null ? {} : { 'aegis.injection_score': verdict.score }),
    })
    return verdict
  })

  if (screening.action !== 'allow') {
    audit('output_screening', {
      tool: name,
      request_id: requestId,
      screening_status: screening.status,
      screening_action: screening.action,
      injection_score: screening.score,
    })
  }

  const screened = applyProvenance(result, { tool: name, requestId, effect, screening })
  return { ...screened, _meta: { ...screened._meta, ...meta } }
}

function approvalMeta(record: ApprovalRecord): Record<string, unknown> {
  return {
    'aegis/request_id': record.request_id,
    'aegis/effect': record.effect,
    'aegis/approval_status': record.status,
  }
}

/**
 * Handles a call whose policy decision is `approve`. The tool executes only after a human
 * has approved the request, and only once in total.
 */
async function gateOnApproval(
  ctx: GatewayContext,
  identity: CallerIdentity,
  name: string,
  args: Record<string, unknown>,
  effect: ToolEffect,
): Promise<CallToolResult> {
  if (!ctx.approvals) {
    // Fail closed: with no durable store there is nowhere to record a decision.
    return refuse('APPROVAL_REQUIRED', `"${name}" requires approval, which is not configured`)
  }

  let outcome
  try {
    outcome = await withSpan(
      'aegis.approval',
      { 'aegis.tool': name, 'aegis.effect': effect },
      async (span) => {
        const resolved = await ctx.approvals!.resolve(identity, name, args, effect)
        span.setAttributes({
          'aegis.approval_request_id': resolved.record.request_id,
          'aegis.approval_outcome': resolved.kind,
          'aegis.approval_status': resolved.record.status,
        })
        return resolved
      },
    )
  } catch (error) {
    // The approval store is unreachable. Fail closed: an irreversible tool must not run
    // when its decision cannot be recorded or looked up.
    return refuse(
      'APPROVAL_REQUIRED',
      `"${name}" requires approval, but the approval store is unavailable: ${String(error)}`,
    )
  }
  const record = outcome.record
  audit('approval', {
    tool: name,
    approval_request_id: record.request_id,
    approval_outcome: outcome.kind,
    approval_status: record.status,
    decided_by: record.decided_by,
  })

  switch (outcome.kind) {
    case 'pending':
      if (outcome.created) await ctx.notify?.('approval_requested', record)
      return refuse(
        'APPROVAL_REQUIRED',
        `"${name}" is ${effect} and is waiting for approval until ${record.expires_at.toISOString()}`,
        approvalMeta(record),
      )

    case 'rejected':
      return refuse(
        'APPROVAL_REJECTED',
        `"${name}" was rejected${record.decision_reason ? `: ${record.decision_reason}` : ''}`,
        approvalMeta(record),
      )

    case 'timeout':
      return refuse(
        'APPROVAL_TIMEOUT',
        `approval for "${name}" expired before a decision was made`,
        approvalMeta(record),
      )

    case 'in_progress':
      return refuse(
        'APPROVAL_REQUIRED',
        `"${name}" is already executing under request ${record.request_id}`,
        approvalMeta(record),
      )

    case 'completed':
      // The approved action already ran; replay its result rather than repeat it.
      return {
        ...(record.result as CallToolResult),
        _meta: { ...approvalMeta(record), 'aegis/replayed': true },
      }

    case 'approved': {
      let result: CallToolResult
      try {
        result = await execute(ctx, name, args, effect, record.request_id, {
          'aegis/approved_by': record.decided_by,
        })
      } catch (error) {
        // The claimed request stays out of the way of a retry: the row is left 'executing',
        // so a repeat resolves to 'in_progress' rather than running the tool a second time.
        await ctx.approvals.markFailed(record.request_id, String(error)).catch(() => {})
        return refuse('TOOL_EXECUTION_FAILED', `call to "${name}" failed: ${String(error)}`)
      }
      // The irreversible action has already run. A failure to record completion must not
      // turn a success into a reported failure, so it is best-effort and logged only.
      await ctx.approvals.markCompleted(record.request_id, result).catch((error: unknown) => {
        process.stderr.write(
          `failed to record completion of ${record.request_id}: ${String(error)}\n`,
        )
      })
      return result
    }
  }
}

/** Every path out of the pipeline ends here, so the outcome is always recorded once. */
function conclude(
  span: Span,
  startedAt: number,
  requestId: string,
  name: string,
  result: CallToolResult,
): CallToolResult {
  const meta = result._meta ?? {}
  const errorCode = meta['aegis/error_code'] as string | undefined
  const provenance = meta['aegis/provenance'] as
    { screening?: { score: number | null } } | undefined
  const latencyMs = Date.now() - startedAt
  const executionStatus = errorCode ? 'refused' : 'completed'

  span.setAttributes({
    'aegis.execution_status': executionStatus,
    'aegis.latency_ms': latencyMs,
    ...(errorCode ? { 'aegis.error_code': errorCode } : {}),
    ...(meta['aegis/effect'] ? { 'aegis.effect': String(meta['aegis/effect']) } : {}),
  })

  audit('decision', {
    request_id: requestId,
    tool: name,
    execution_status: executionStatus,
    error_code: errorCode,
    effect: meta['aegis/effect'],
    approval_request_id: meta['aegis/request_id'],
    injection_score: provenance?.screening?.score,
    latency_ms: latencyMs,
  })
  return result
}

export async function callTool(
  ctx: GatewayContext,
  name: string,
  args: Record<string, unknown>,
): Promise<CallToolResult> {
  const requestId = randomUUID()
  const startedAt = Date.now()

  return tracer.startActiveSpan(
    'aegis.tool_call',
    {
      attributes: {
        'aegis.request_id': requestId,
        'aegis.tool': name,
        'aegis.agent_id': ctx.identity?.agent_id ?? 'anonymous',
        'aegis.role': ctx.identity?.role ?? 'anonymous',
      },
    },
    async (span) => {
      try {
        audit('tool_requested', {
          request_id: requestId,
          tool: name,
          agent_id: ctx.identity?.agent_id,
          role: ctx.identity?.role,
          argument_names: argumentNames(args),
        })

        const authorization = await withSpan('aegis.authorize', { 'aegis.tool': name }, (child) => {
          const decision = authorize(ctx.policy, ctx.identity, name)
          child.setAttributes({
            'aegis.policy_decision': decision.decision,
            'aegis.approval_required': decision.decision === 'approve',
            ...(decision.decision === 'deny'
              ? { 'aegis.error_code': decision.code }
              : { 'aegis.effect': decision.effect }),
          })
          audit('authorization', {
            request_id: requestId,
            tool: name,
            agent_id: ctx.identity?.agent_id,
            role: ctx.identity?.role,
            policy_decision: decision.decision,
            effect: decision.decision === 'deny' ? undefined : decision.effect,
            error_code: decision.decision === 'deny' ? decision.code : undefined,
          })
          return decision
        })

        if (authorization.decision === 'deny') {
          return conclude(
            span,
            startedAt,
            requestId,
            name,
            refuse(authorization.code, authorization.reason),
          )
        }

        const tool = (await upstreamTools(ctx.upstream)).find(
          (candidate) => candidate.name === name,
        )
        if (!tool) {
          return conclude(
            span,
            startedAt,
            requestId,
            name,
            refuse('TOOL_EXECUTION_FAILED', `the MCP server does not expose "${name}"`),
          )
        }

        const validation = await withSpan(
          'aegis.validate_arguments',
          { 'aegis.tool': name, 'aegis.argument_names': argumentNames(args) },
          (child) => {
            const outcome = validateArguments(name, tool.inputSchema, args)
            child.setAttribute('aegis.arguments_valid', outcome.valid)
            return outcome
          },
        )
        if (!validation.valid) {
          audit('validation_failed', {
            request_id: requestId,
            tool: name,
            reason: validation.reason,
            argument_names: argumentNames(args),
          })
          return conclude(
            span,
            startedAt,
            requestId,
            name,
            refuse('INVALID_ARGUMENTS', validation.reason),
          )
        }

        // Approval is gated after validation so nobody is asked to approve a malformed call.
        // Policy is re-evaluated above on every resume, so an approval granted earlier cannot
        // execute a tool the policy has since denied.
        if (authorization.decision === 'approve') {
          if (!ctx.identity) {
            return conclude(
              span,
              startedAt,
              requestId,
              name,
              refuse('UNAUTHORIZED_CALLER', 'no caller identity on the request'),
            )
          }
          return conclude(
            span,
            startedAt,
            requestId,
            name,
            await gateOnApproval(ctx, ctx.identity, name, args, authorization.effect),
          )
        }

        // Only an authorized, validated, auto-executable call reaches the MCP server.
        try {
          return conclude(
            span,
            startedAt,
            requestId,
            name,
            await execute(ctx, name, args, authorization.effect, requestId),
          )
        } catch (error) {
          span.setStatus({ code: SpanStatusCode.ERROR, message: String(error) })
          return conclude(
            span,
            startedAt,
            requestId,
            name,
            refuse('MCP_CONNECTION_ERROR', `call to "${name}" failed: ${String(error)}`),
          )
        }
      } catch (error) {
        // Last-resort fail-closed net: any unexpected error in the request path (a dependency
        // failing, listTools timing out) becomes a structured refusal, never an unhandled
        // rejection and never a leaked stack trace. The action did not run.
        span.setStatus({ code: SpanStatusCode.ERROR, message: String(error) })
        return conclude(
          span,
          startedAt,
          requestId,
          name,
          refuse('TOOL_EXECUTION_FAILED', `request for "${name}" could not be completed safely`),
        )
      } finally {
        span.end()
      }
    },
  )
}
