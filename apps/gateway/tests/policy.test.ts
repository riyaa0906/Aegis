import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { authorize, loadPolicy, parsePolicy, type Policy } from '../src/policy.js'
import { parseIdentity } from '../src/identity.js'

const developmentPolicyPath = fileURLToPath(
  new URL('../../../policies/development.yaml', import.meta.url),
)

const support = { agent_id: 'agent-1', role: 'support_agent' }
const admin = { agent_id: 'agent-2', role: 'admin_agent' }
const stranger = { agent_id: 'agent-3', role: 'marketing_agent' }

const policy = loadPolicy(developmentPolicyPath)

describe('parseIdentity', () => {
  it('accepts a complete identity', () => {
    expect(parseIdentity('agent-1', 'support_agent')).toEqual({
      agent_id: 'agent-1',
      role: 'support_agent',
    })
  })

  it('rejects missing, blank or non-string values', () => {
    expect(parseIdentity(undefined, 'support_agent')).toBeNull()
    expect(parseIdentity('agent-1', undefined)).toBeNull()
    expect(parseIdentity('agent-1', '   ')).toBeNull()
    expect(parseIdentity(['agent-1'], 'support_agent')).toBeNull()
  })
})

describe('policy loading', () => {
  it('loads the shipped development policy', () => {
    expect(Object.keys(policy.roles)).toEqual(['support_agent', 'admin_agent'])
    expect(policy.roles.support_agent?.tools.send_email).toBe('deny')
  })

  it('rejects a missing policy file', () => {
    expect(() => loadPolicy('/nonexistent/aegis-policy.yaml')).toThrow(/could not be read/)
  })

  it('rejects malformed YAML', () => {
    expect(() => parsePolicy('roles: [unclosed')).toThrow(/not valid YAML/)
  })

  it('rejects a structurally invalid policy', () => {
    expect(() => parsePolicy('rolez:\n  support_agent:\n    tools: {}\n')).toThrow(/malformed/)
    expect(() => parsePolicy('roles:\n  support_agent: {}\n')).toThrow(/malformed/)
    expect(() =>
      parsePolicy('roles:\n  support_agent:\n    tools:\n      send_email: maybe\n'),
    ).toThrow(/malformed/)
    expect(() => parsePolicy('')).toThrow(/malformed/)
  })
})

describe('authorize', () => {
  it('returns auto for a tool the policy grants automatically', () => {
    expect(authorize(policy, support, 'get_payment_status')).toEqual({
      decision: 'auto',
      effect: 'READ_ONLY',
    })
  })

  it('returns approve for a tool the policy holds for a human', () => {
    expect(authorize(policy, support, 'github_create_issue')).toEqual({
      decision: 'approve',
      effect: 'WRITE_IRREVERSIBLE',
    })
    expect(authorize(policy, admin, 'send_email')).toEqual({
      decision: 'approve',
      effect: 'WRITE_IRREVERSIBLE',
    })
  })

  it('denies a tool the policy marks deny', () => {
    expect(authorize(policy, support, 'send_email')).toMatchObject({
      decision: 'deny',
      code: 'TOOL_NOT_ALLOWED',
    })
  })

  it('denies a caller without an identity', () => {
    expect(authorize(policy, null, 'get_payment_status')).toMatchObject({
      decision: 'deny',
      code: 'UNAUTHORIZED_CALLER',
    })
  })

  it('denies a role the policy does not mention', () => {
    expect(authorize(policy, stranger, 'get_payment_status')).toMatchObject({
      decision: 'deny',
      code: 'UNAUTHORIZED_CALLER',
    })
  })

  it('denies a tool the policy does not mention', () => {
    const sparse = parsePolicy(
      'roles:\n  support_agent:\n    tools:\n      get_github_issue: auto\n',
    )
    expect(authorize(sparse, support, 'get_payment_status')).toMatchObject({
      decision: 'deny',
      code: 'TOOL_NOT_ALLOWED',
    })
  })

  it('denies a tool Aegis has never classified, however the policy is written', () => {
    const overreaching = parsePolicy(
      'roles:\n  support_agent:\n    tools:\n      drop_database: auto\n',
    )
    expect(authorize(overreaching, support, 'drop_database')).toMatchObject({
      decision: 'deny',
      code: 'TOOL_NOT_ALLOWED',
    })
  })

  it('denies a DENIED tool even when the policy tries to grant it', () => {
    const overreaching: Policy = parsePolicy(
      'roles:\n  admin_agent:\n    tools:\n      delete_repository: auto\n',
    )
    expect(authorize(overreaching, admin, 'delete_repository')).toMatchObject({
      decision: 'deny',
      code: 'TOOL_DENIED',
    })
  })
})
