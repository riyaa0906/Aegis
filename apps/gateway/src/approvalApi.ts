import type { IncomingMessage, ServerResponse } from 'node:http'
import type { ApprovalStore } from './approval.js'

/**
 * The endpoints a human (or a Slack action, or a script) uses to decide an approval.
 * These are not authenticated yet; production hardening adds that.
 */
export async function handleApprovalRequest(
  store: ApprovalStore,
  req: IncomingMessage,
  res: ServerResponse,
  path: string,
): Promise<boolean> {
  const send = (status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json' })
    res.end(JSON.stringify(body))
  }

  if (path === '/approvals' && req.method === 'GET') {
    send(200, { approvals: await store.listPending() })
    return true
  }

  const decision = /^\/approvals\/([0-9a-f-]{36})\/(approve|reject)$/.exec(path)
  if (decision && req.method === 'POST') {
    const [, requestId, action] = decision as unknown as [string, string, 'approve' | 'reject']
    const body = await readJson(req)
    const decidedBy = typeof body.decided_by === 'string' ? body.decided_by.trim() : ''
    if (!decidedBy) {
      send(400, { error: 'decided_by is required' })
      return true
    }

    const record =
      action === 'approve'
        ? await store.approve(requestId, decidedBy)
        : await store.reject(
            requestId,
            decidedBy,
            typeof body.reason === 'string' ? body.reason : undefined,
          )

    if (!record) send(404, { error: `no approval request ${requestId}` })
    else send(200, { approval: record })
    return true
  }

  return false
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(chunk as Buffer)
  if (chunks.length === 0) return {}
  try {
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    return typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {}
  } catch {
    return {}
  }
}
