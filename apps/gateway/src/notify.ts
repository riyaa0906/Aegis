import type { ApprovalRecord } from './approval.js'

export type ApprovalEvent = 'approval_requested' | 'approval_escalated'
export type Notifier = (event: ApprovalEvent, record: ApprovalRecord) => Promise<void>

/**
 * Posts approval events to a webhook. The payload carries a `text` field so a Slack
 * incoming webhook renders it directly. A failed notification is logged, never fatal: the
 * approval request itself is already durable.
 */
export function createNotifier(webhookUrl: string | undefined): Notifier {
  if (!webhookUrl) return async () => {}

  return async (event, record) => {
    const summary =
      event === 'approval_requested'
        ? `Approval required: ${record.tool} (${record.effect}) requested by ${record.agent_id}`
        : `Approval expired without a decision: ${record.tool} requested by ${record.agent_id}`
    const details = [
      summary,
      `request_id: ${record.request_id}`,
      `arguments: ${JSON.stringify(record.arguments)}`,
    ].join('\n')

    try {
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          text: details,
          event,
          request_id: record.request_id,
          agent_id: record.agent_id,
          role: record.role,
          tool: record.tool,
          effect: record.effect,
          arguments: record.arguments,
          expires_at: record.expires_at,
        }),
      })
    } catch (error) {
      process.stderr.write(`approval notification failed: ${String(error)}\n`)
    }
  }
}
