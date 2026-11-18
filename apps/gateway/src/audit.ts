import { trace } from '@opentelemetry/api'

/**
 * Structured audit trail of security decisions, one JSON line per event on stderr
 * (stdout belongs to the MCP protocol in stdio mode).
 *
 * What is recorded is deliberately narrow: who called, which tool, what Aegis decided and
 * why. Argument *values* and tool output never go in here -- they are the parts most likely
 * to carry customer data, credentials or an attacker's payload. Argument names are recorded
 * instead, which is enough to explain a validation failure.
 */
export type AuditEvent =
  | 'tool_requested'
  | 'authorization'
  | 'validation_failed'
  | 'approval'
  | 'output_screening'
  | 'decision'

export function audit(event: AuditEvent, fields: Record<string, unknown>): void {
  const spanContext = trace.getActiveSpan()?.spanContext()
  const entry = {
    ts: new Date().toISOString(),
    event,
    trace_id: spanContext?.traceId,
    span_id: spanContext?.spanId,
    ...fields,
  }
  // stderr, not stdout: stdout is the MCP protocol channel in stdio mode.
  console.error(JSON.stringify(entry))
}

/** Argument names only: never their values. */
export function argumentNames(args: Record<string, unknown>): string[] {
  return Object.keys(args).sort()
}
