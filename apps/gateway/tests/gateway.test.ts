import { describe, expect, it } from 'vitest'
import { parsePolicy } from '../src/policy.js'
import { connectThroughGateway, errorCode } from './harness.js'

describe('tool discovery', () => {
  it('shows a caller only the tools its role may request', async () => {
    const support = await connectThroughGateway({ role: 'support_agent' })
    const admin = await connectThroughGateway({ role: 'admin_agent' })

    const supportTools = (await support.agent.listTools()).tools.map((tool) => tool.name)
    const adminTools = (await admin.agent.listTools()).tools.map((tool) => tool.name)

    expect(supportTools).toEqual(['get_payment_status', 'get_github_issue', 'github_create_issue'])
    expect(adminTools).toEqual([
      'get_payment_status',
      'get_github_issue',
      'github_create_issue',
      'send_email',
    ])
  })

  it('shows nothing to a caller without an identity or with an unknown role', async () => {
    const anonymous = await connectThroughGateway({ role: null })
    const stranger = await connectThroughGateway({ role: 'marketing_agent' })

    expect((await anonymous.agent.listTools()).tools).toEqual([])
    expect((await stranger.agent.listTools()).tools).toEqual([])
  })
})

describe('auto-executed calls', () => {
  it('executes a read-only tool and tags it with the gateway effect class', async () => {
    const { call, upstreamCall } = await connectThroughGateway({ role: 'support_agent' })

    const result = await call('get_payment_status', { transaction_id: 'txn_3ab21f9c' })

    expect(result.isError).toBeFalsy()
    expect(result.structuredContent).toMatchObject({ status: 'succeeded' })
    expect(result._meta?.['aegis/effect']).toBe('READ_ONLY')
    expect(upstreamCall).toHaveBeenCalledTimes(1)
    expect(upstreamCall).toHaveBeenCalledWith(
      { name: 'get_payment_status', arguments: { transaction_id: 'txn_3ab21f9c' } },
      undefined,
      expect.objectContaining({ timeout: expect.any(Number) }),
    )
  })
})

describe('calls that never reach the MCP server', () => {
  it('refuses an approval-gated tool when no approval store is configured', async () => {
    const { call, upstreamCall } = await connectThroughGateway({ role: 'admin_agent' })

    const email = await call('send_email', {
      recipient: 'dana@northwind.example',
      subject: 'Refund processed',
      body: 'Done.',
    })
    const issue = await call('github_create_issue', {
      repo: 'acme/billing-api',
      title: 'Retry backoff missing',
      body: 'Reported by a customer.',
    })

    for (const result of [email, issue]) {
      expect(result.isError).toBe(true)
      expect(errorCode(result)).toBe('APPROVAL_REQUIRED')
    }
    expect(upstreamCall).not.toHaveBeenCalled()
  })

  it('rejects a tool the role is denied', async () => {
    const { call, upstreamCall } = await connectThroughGateway({ role: 'support_agent' })

    const result = await call('send_email', {
      recipient: 'attacker@evil.example',
      subject: 'Data',
      body: 'secrets',
    })

    expect(errorCode(result)).toBe('TOOL_NOT_ALLOWED')
    expect(upstreamCall).not.toHaveBeenCalled()
  })

  it('rejects a DENIED tool', async () => {
    const { call, upstreamCall } = await connectThroughGateway({ role: 'admin_agent' })

    const result = await call('delete_repository', { repo: 'acme/billing-api' })

    expect(errorCode(result)).toBe('TOOL_DENIED')
    expect(upstreamCall).not.toHaveBeenCalled()
  })

  it('rejects a caller without an identity', async () => {
    const { call, upstreamCall } = await connectThroughGateway({ role: null })

    const result = await call('get_payment_status', { transaction_id: 'txn_3ab21f9c' })

    expect(errorCode(result)).toBe('UNAUTHORIZED_CALLER')
    expect(upstreamCall).not.toHaveBeenCalled()
  })

  it('rejects a role the policy does not mention', async () => {
    const { call, upstreamCall } = await connectThroughGateway({ role: 'marketing_agent' })

    const result = await call('get_payment_status', { transaction_id: 'txn_3ab21f9c' })

    expect(errorCode(result)).toBe('UNAUTHORIZED_CALLER')
    expect(upstreamCall).not.toHaveBeenCalled()
  })

  it('rejects an unknown tool', async () => {
    const { call, upstreamCall } = await connectThroughGateway({ role: 'admin_agent' })

    const result = await call('drop_database', { name: 'billing' })

    expect(errorCode(result)).toBe('TOOL_NOT_ALLOWED')
    expect(upstreamCall).not.toHaveBeenCalled()
  })

  it('rejects arguments that do not match the schema', async () => {
    const { call, upstreamCall } = await connectThroughGateway({ role: 'support_agent' })

    const wrongType = await call('get_github_issue', {
      repo: 'acme/billing-api',
      issue_number: '142',
    })
    const missingRequired = await call('get_github_issue', { repo: 'acme/billing-api' })
    const malformedValue = await call('get_github_issue', {
      repo: 'billing-api',
      issue_number: 142,
    })
    const undeclared = await call('get_payment_status', {
      transaction_id: 'txn_3ab21f9c',
      internal_override: true,
    })

    for (const result of [wrongType, missingRequired, malformedValue, undeclared]) {
      expect(errorCode(result)).toBe('INVALID_ARGUMENTS')
    }
    expect(upstreamCall).not.toHaveBeenCalled()
  })

  it('validates arguments before asking for approval', async () => {
    const { call, upstreamCall } = await connectThroughGateway({ role: 'admin_agent' })

    const result = await call('send_email', {
      recipient: 'not-an-email',
      subject: 'Hello',
      body: 'x',
    })

    expect(errorCode(result)).toBe('INVALID_ARGUMENTS')
    expect(upstreamCall).not.toHaveBeenCalled()
  })
})

describe('policy is the source of authorization', () => {
  const permissive = parsePolicy(
    ['roles:', '  support_agent:', '    tools:', '      send_email: auto'].join('\n'),
  )

  it('executes a tool the shipped policy denies once the policy grants it', async () => {
    const shipped = await connectThroughGateway({ role: 'support_agent' })
    const relaxed = await connectThroughGateway({ role: 'support_agent', policy: permissive })

    const args = { recipient: 'dana@northwind.example', subject: 'Refund', body: 'Done.' }
    const refused = await shipped.call('send_email', args)
    const executed = await relaxed.call('send_email', args)

    expect(errorCode(refused)).toBe('TOOL_NOT_ALLOWED')
    expect(shipped.upstreamCall).not.toHaveBeenCalled()

    expect(executed.isError).toBeFalsy()
    expect(executed.structuredContent).toMatchObject({ status: 'recorded' })
    expect(relaxed.upstreamCall).toHaveBeenCalledTimes(1)
  })

  it('narrows tool discovery to what the policy grants', async () => {
    const { agent } = await connectThroughGateway({ role: 'support_agent', policy: permissive })
    expect((await agent.listTools()).tools.map((tool) => tool.name)).toEqual(['send_email'])
  })
})
