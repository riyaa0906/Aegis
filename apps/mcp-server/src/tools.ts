import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js'
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import type { ToolEffect } from '@aegis/shared-types'
import { z } from 'zod'
import { createIssue, getIssue, getPayment, recordEmail } from './store.js'

/**
 * Effect classification is declared here, next to the tool, and published to clients
 * as MCP annotations plus an `aegis/effect` meta field. Aegis keeps its own copy of
 * this classification: the gateway must not depend on a server's self-report.
 */
function effectMetadata(effect: ToolEffect): {
  annotations: ToolAnnotations
  _meta: Record<string, unknown>
} {
  const readOnly = effect === 'READ_ONLY'
  return {
    annotations: {
      readOnlyHint: readOnly,
      destructiveHint: !readOnly,
      idempotentHint: readOnly,
      openWorldHint: true,
    },
    _meta: { 'aegis/effect': effect },
  }
}

const repoSchema = z
  .string()
  .regex(/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/, 'repo must be in "owner/name" form')

function ok(structured: Record<string, unknown>) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(structured, null, 2) }],
    structuredContent: structured,
  }
}

function failed(message: string) {
  return { content: [{ type: 'text' as const, text: message }], isError: true }
}

export function registerTools(server: McpServer): void {
  server.registerTool(
    'get_payment_status',
    {
      description: 'Look up the current status of a payment transaction.',
      inputSchema: { transaction_id: z.string().min(1) },
      outputSchema: {
        transaction_id: z.string(),
        status: z.enum(['pending', 'succeeded', 'failed', 'refunded']),
        amount_cents: z.int(),
        currency: z.string(),
        customer_email: z.string(),
        created_at: z.string(),
      },
      ...effectMetadata('READ_ONLY'),
    },
    ({ transaction_id }) => {
      const payment = getPayment(transaction_id)
      if (!payment) return failed(`No transaction found with id ${transaction_id}`)
      return ok(payment)
    },
  )

  server.registerTool(
    'get_github_issue',
    {
      description: 'Read a GitHub issue, including its body and current state.',
      inputSchema: { repo: repoSchema, issue_number: z.int().positive() },
      outputSchema: {
        repo: z.string(),
        number: z.int(),
        title: z.string(),
        body: z.string(),
        state: z.enum(['open', 'closed']),
        author: z.string(),
        created_at: z.string(),
      },
      ...effectMetadata('READ_ONLY'),
    },
    ({ repo, issue_number }) => {
      const issue = getIssue(repo, issue_number)
      if (!issue) return failed(`No issue ${repo}#${issue_number}`)
      return ok(issue)
    },
  )

  server.registerTool(
    'github_create_issue',
    {
      description: 'Create a new GitHub issue in a repository.',
      inputSchema: {
        repo: repoSchema,
        title: z.string().min(1).max(256),
        body: z.string().max(65536),
      },
      outputSchema: {
        repo: z.string(),
        number: z.int(),
        url: z.string(),
        state: z.enum(['open', 'closed']),
        created_at: z.string(),
      },
      ...effectMetadata('WRITE_IRREVERSIBLE'),
    },
    ({ repo, title, body }) => {
      const issue = createIssue(repo, title, body)
      return ok({
        repo: issue.repo,
        number: issue.number,
        url: `https://github.com/${issue.repo}/issues/${issue.number}`,
        state: issue.state,
        created_at: issue.created_at,
      })
    },
  )

  server.registerTool(
    'send_email',
    {
      description: 'Send an email to a recipient.',
      inputSchema: {
        recipient: z.email(),
        subject: z.string().min(1).max(256),
        body: z.string().max(65536),
      },
      outputSchema: {
        message_id: z.string(),
        recipient: z.string(),
        status: z.literal('recorded'),
        recorded_at: z.string(),
      },
      ...effectMetadata('WRITE_IRREVERSIBLE'),
    },
    ({ recipient, subject, body }) => {
      const email = recordEmail(recipient, subject, body)
      return ok({
        message_id: email.message_id,
        recipient: email.recipient,
        // Sandbox: recorded in the outbox, never handed to a mail transport.
        status: 'recorded',
        recorded_at: email.recorded_at,
      })
    },
  )
}
