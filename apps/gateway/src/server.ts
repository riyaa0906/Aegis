import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { callTool, listAllowedTools, type GatewayContext } from './pipeline.js'

/** The MCP surface an agent talks to. Every tool call goes through the Aegis pipeline. */
export function createGatewayServer(ctx: GatewayContext): Server {
  const server = new Server(
    { name: 'aegis-gateway', version: '0.1.0' },
    { capabilities: { tools: {} } },
  )

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: await listAllowedTools(ctx),
  }))

  server.setRequestHandler(CallToolRequestSchema, async (request) =>
    callTool(ctx, request.params.name, request.params.arguments ?? {}),
  )

  return server
}
