import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'
import { beforeEach, describe, expect, it } from 'vitest'
import { createServer } from '../src/server.js'
import { outbox } from '../src/store.js'

let client: Client

beforeEach(async () => {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  client = new Client({ name: 'test-client', version: '0.0.0' })
  await Promise.all([createServer().connect(serverTransport), client.connect(clientTransport)])
})

const call = (name: string, args: Record<string, unknown>) =>
  client.callTool({ name, arguments: args }) as Promise<CallToolResult>

describe('tool registration', () => {
  it('exposes the four tools with their effect classification', async () => {
    const { tools } = await client.listTools()
    const byName = Object.fromEntries(tools.map((tool) => [tool.name, tool]))

    expect(Object.keys(byName).sort()).toEqual([
      'get_github_issue',
      'get_payment_status',
      'github_create_issue',
      'send_email',
    ])
    expect(byName.get_payment_status?._meta?.['aegis/effect']).toBe('READ_ONLY')
    expect(byName.get_github_issue?.annotations?.readOnlyHint).toBe(true)
    expect(byName.send_email?._meta?.['aegis/effect']).toBe('WRITE_IRREVERSIBLE')
    expect(byName.github_create_issue?.annotations?.destructiveHint).toBe(true)
  })

  it('publishes an input schema for every tool', async () => {
    const { tools } = await client.listTools()
    for (const tool of tools) {
      expect(tool.inputSchema.type).toBe('object')
      expect(tool.outputSchema?.type).toBe('object')
    }
  })
})

describe('get_payment_status', () => {
  it('returns the payment for a known transaction', async () => {
    const result = await call('get_payment_status', { transaction_id: 'txn_3ab21f9c' })

    expect(result.isError).toBeFalsy()
    expect(result.structuredContent).toMatchObject({
      transaction_id: 'txn_3ab21f9c',
      status: 'succeeded',
      amount_cents: 4999,
      currency: 'USD',
    })
  })

  it('reports an unknown transaction as an error result', async () => {
    const result = await call('get_payment_status', { transaction_id: 'txn_missing' })
    expect(result.isError).toBe(true)
  })

  it('rejects a missing argument', async () => {
    const result = await call('get_payment_status', {})
    expect(result.isError).toBe(true)
    expect(result.structuredContent).toBeUndefined()
  })
})

describe('get_github_issue', () => {
  it('returns the issue body', async () => {
    const result = await call('get_github_issue', { repo: 'acme/billing-api', issue_number: 142 })

    expect(result.structuredContent).toMatchObject({
      repo: 'acme/billing-api',
      number: 142,
      state: 'open',
    })
    expect(String((result.structuredContent as { body: string }).body)).toContain('503')
  })

  it('does not coerce a numeric string into a number', async () => {
    const result = await call('get_github_issue', { repo: 'acme/billing-api', issue_number: '142' })
    expect(result.isError).toBe(true)
  })

  it('rejects a malformed repo', async () => {
    const result = await call('get_github_issue', { repo: 'billing-api', issue_number: 142 })
    expect(result.isError).toBe(true)
  })
})

describe('github_create_issue', () => {
  it('creates an issue and returns its location', async () => {
    const result = await call('github_create_issue', {
      repo: 'acme/support-portal',
      title: 'Duplicate refund email',
      body: 'Two receipts were sent for one refund.',
    })

    const created = result.structuredContent as { repo: string; number: number; url: string }
    expect(created.repo).toBe('acme/support-portal')
    expect(created.url).toBe(`https://github.com/acme/support-portal/issues/${created.number}`)

    const readBack = await call('get_github_issue', {
      repo: 'acme/support-portal',
      issue_number: created.number,
    })
    expect(readBack.structuredContent).toMatchObject({ title: 'Duplicate refund email' })
  })

  it('rejects an empty title', async () => {
    const result = await call('github_create_issue', { repo: 'acme/web', title: '', body: 'x' })
    expect(result.isError).toBe(true)
  })
})

describe('send_email', () => {
  it('records the email instead of delivering it', async () => {
    const before = outbox.length
    const result = await call('send_email', {
      recipient: 'dana@northwind.example',
      subject: 'Refund processed',
      body: 'Your refund is on its way.',
    })

    expect(result.structuredContent).toMatchObject({
      recipient: 'dana@northwind.example',
      status: 'recorded',
    })
    expect(outbox).toHaveLength(before + 1)
    expect(outbox.at(-1)?.subject).toBe('Refund processed')
  })

  it('rejects an invalid recipient without recording anything', async () => {
    const before = outbox.length
    const result = await call('send_email', {
      recipient: 'not-an-email',
      subject: 'Hello',
      body: 'x',
    })

    expect(result.isError).toBe(true)
    expect(outbox).toHaveLength(before)
  })
})
