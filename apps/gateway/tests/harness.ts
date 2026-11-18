import { fileURLToPath } from 'node:url'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'
import { createServer as createMcpServer } from '@aegis/mcp-server/server'
import { vi } from 'vitest'
import type { ApprovalStore } from '../src/approval.js'
import type { Notifier } from '../src/notify.js'
import type { Classifier } from '../src/screening.js'
import { loadPolicy, type Policy } from '../src/policy.js'
import { createGatewayServer } from '../src/server.js'

export const developmentPolicy = loadPolicy(
  fileURLToPath(new URL('../../../policies/development.yaml', import.meta.url)),
)

/** agent -> gateway -> upstream MCP client -> MCP server, all in process. */
export async function connectThroughGateway(options: {
  role: string | null
  policy?: Policy
  approvals?: ApprovalStore | null
  notify?: Notifier
  classifier?: Classifier | null
}) {
  const [upstreamSide, mcpSide] = InMemoryTransport.createLinkedPair()
  const upstream = new Client({ name: 'gateway-upstream', version: '0.0.0' })
  await Promise.all([createMcpServer().connect(mcpSide), upstream.connect(upstreamSide)])
  const upstreamCall = vi.spyOn(upstream, 'callTool')

  const identity = options.role === null ? null : { agent_id: 'agent-1', role: options.role }
  const [agentSide, gatewaySide] = InMemoryTransport.createLinkedPair()
  const agent = new Client({ name: 'agent', version: '0.0.0' })
  await Promise.all([
    createGatewayServer({
      upstream,
      policy: options.policy ?? developmentPolicy,
      identity,
      approvals: options.approvals,
      notify: options.notify,
      classifier: options.classifier,
    }).connect(gatewaySide),
    agent.connect(agentSide),
  ])

  const call = (name: string, args: Record<string, unknown>) =>
    agent.callTool({ name, arguments: args }) as Promise<CallToolResult>

  return { agent, call, upstreamCall }
}

export const errorCode = (result: CallToolResult) => result._meta?.['aegis/error_code']
export const requestId = (result: CallToolResult) => String(result._meta?.['aegis/request_id'])

export const provenance = (result: CallToolResult) =>
  result._meta?.['aegis/provenance'] as {
    source: string
    tool: string
    trust: string
    request_id: string
    screening: { status: string; action: string; score: number | null }
  }

export const textOf = (result: CallToolResult) =>
  result.content.map((block) => (block.type === 'text' ? block.text : '')).join('\n')
