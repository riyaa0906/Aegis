import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { ApprovalStore } from './approval.js'
import { handleApprovalRequest } from './approvalApi.js'
import { connectCache } from './cache.js'
import { parseIdentity } from './identity.js'
import { createNotifier, type Notifier } from './notify.js'
import { loadPolicy, type Policy } from './policy.js'
import { createHttpClassifier, type Classifier } from './screening.js'
import { createGatewayServer } from './server.js'
import { initTelemetry } from './telemetry.js'

const GATEWAY_PATH = '/mcp'
const DEFAULT_APPROVAL_TIMEOUT_MS = 15 * 60 * 1000
const DEFAULT_SWEEP_INTERVAL_MS = 30 * 1000

type Services = {
  upstream: Client
  policy: Policy
  approvals: ApprovalStore | null
  notify: Notifier
  classifier: Classifier | null
}

async function connectUpstream(): Promise<Client> {
  const client = new Client({ name: 'aegis-gateway', version: '0.1.0' })
  const url = process.env.AEGIS_MCP_URL
  const command = process.env.AEGIS_MCP_COMMAND
  if (url) {
    await client.connect(new StreamableHTTPClientTransport(new URL(url)))
  } else if (command) {
    await client.connect(
      new StdioClientTransport({ command, args: process.env.AEGIS_MCP_ARGS?.split(' ') ?? [] }),
    )
  } else {
    throw new Error('set AEGIS_MCP_URL or AEGIS_MCP_COMMAND to reach the MCP server')
  }
  return client
}

async function openApprovals(): Promise<ApprovalStore | null> {
  const databaseUrl = process.env.AEGIS_DATABASE_URL
  if (!databaseUrl) return null
  const redisUrl = process.env.AEGIS_REDIS_URL
  return ApprovalStore.open(databaseUrl, {
    timeoutMs: Number(process.env.AEGIS_APPROVAL_TIMEOUT_MS ?? DEFAULT_APPROVAL_TIMEOUT_MS),
    cache: redisUrl ? await connectCache(redisUrl) : null,
  })
}

/** Times out overdue approvals and escalates them, so nothing waits forever. */
function startApprovalSweep(store: ApprovalStore, notify: Notifier): void {
  const interval = Number(process.env.AEGIS_APPROVAL_SWEEP_MS ?? DEFAULT_SWEEP_INTERVAL_MS)
  setInterval(() => {
    void (async () => {
      try {
        for (const record of await store.expireOverdue()) {
          await notify('approval_escalated', record)
          await store.markEscalated(record.request_id)
        }
      } catch (error) {
        process.stderr.write(`approval sweep failed: ${String(error)}\n`)
      }
    })()
  }, interval).unref()
}

async function handleHttpRequest(
  services: Services,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const path = req.url?.split('?')[0] ?? ''

  if (services.approvals && (await handleApprovalRequest(services.approvals, req, res, path))) {
    return
  }
  if (path !== GATEWAY_PATH) {
    res.writeHead(404).end()
    return
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { Allow: 'POST' }).end()
    return
  }

  const identity = parseIdentity(req.headers['x-aegis-agent-id'], req.headers['x-aegis-role'])
  const server = createGatewayServer({ ...services, identity })
  const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true })
  res.on('close', () => {
    void transport.close()
    void server.close()
  })
  await server.connect(transport)
  await transport.handleRequest(req, res)
}

async function main(): Promise<void> {
  const shutdownTelemetry = initTelemetry()
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    // Flush pending spans before the process goes away.
    process.once(signal, () => {
      void shutdownTelemetry().finally(() => process.exit(0))
    })
  }

  const policyFile = process.env.AEGIS_POLICY_FILE
  if (!policyFile) throw new Error('set AEGIS_POLICY_FILE to the policy YAML to enforce')

  const classifierUrl = process.env.AEGIS_CLASSIFIER_URL
  const services: Services = {
    policy: loadPolicy(policyFile),
    approvals: await openApprovals(),
    notify: createNotifier(process.env.AEGIS_NOTIFY_WEBHOOK_URL),
    classifier: classifierUrl ? createHttpClassifier(classifierUrl) : null,
    upstream: await connectUpstream(),
  }
  if (!classifierUrl) {
    process.stderr.write(
      'warning: AEGIS_CLASSIFIER_URL is unset, tool output is fenced but not screened\n',
    )
  }
  if (services.approvals) startApprovalSweep(services.approvals, services.notify)

  if (process.argv.includes('--http')) {
    const port = Number(process.env.AEGIS_HTTP_PORT ?? 3000)
    createHttpServer((req, res) => {
      handleHttpRequest(services, req, res).catch((error: unknown) => {
        process.stderr.write(`gateway request failed: ${String(error)}\n`)
        if (!res.headersSent) res.writeHead(500).end()
      })
    }).listen(port, () => {
      process.stderr.write(`aegis gateway listening on http://127.0.0.1:${port}${GATEWAY_PATH}\n`)
    })
    return
  }

  // In stdio mode there is one caller per process, so its identity comes from the environment.
  const identity = parseIdentity(process.env.AEGIS_AGENT_ID, process.env.AEGIS_AGENT_ROLE)
  await createGatewayServer({ ...services, identity }).connect(new StdioServerTransport())
}

main().catch((error: unknown) => {
  process.stderr.write(`aegis gateway failed to start: ${String(error)}\n`)
  process.exit(1)
})
