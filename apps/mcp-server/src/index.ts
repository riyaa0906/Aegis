import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { createServer } from './server.js'

const MCP_PATH = '/mcp'

async function handleHttpRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.url?.split('?')[0] !== MCP_PATH) {
    res.writeHead(404).end()
    return
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { Allow: 'POST' }).end()
    return
  }

  // Stateless: one server + transport per request, so nothing is shared between callers.
  const server = createServer()
  const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true })
  res.on('close', () => {
    void transport.close()
    void server.close()
  })
  await server.connect(transport)
  await transport.handleRequest(req, res)
}

async function main(): Promise<void> {
  if (process.argv.includes('--http')) {
    const port = Number(process.env.MCP_HTTP_PORT ?? 3001)
    createHttpServer((req, res) => {
      handleHttpRequest(req, res).catch((error: unknown) => {
        process.stderr.write(`mcp request failed: ${String(error)}\n`)
        if (!res.headersSent) res.writeHead(500).end()
      })
    }).listen(port, () => {
      process.stderr.write(`aegis mcp-server listening on http://127.0.0.1:${port}${MCP_PATH}\n`)
    })
    return
  }

  await createServer().connect(new StdioServerTransport())
}

main().catch((error: unknown) => {
  process.stderr.write(`aegis mcp-server failed to start: ${String(error)}\n`)
  process.exit(1)
})
