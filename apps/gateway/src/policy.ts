import { readFileSync } from 'node:fs'
import { Ajv } from 'ajv'
import { parse as parseYaml } from 'yaml'
import { POLICY_DECISIONS } from '@aegis/shared-types'
import type { AegisErrorCode, PolicyDecision, ToolEffect } from '@aegis/shared-types'
import type { CallerIdentity } from './identity.js'
import { effectOf } from './effects.js'
import { DEFAULT_SCREENING_CONFIG, type ScreeningConfig } from './screening.js'

export type Policy = {
  roles: Record<string, { tools: Record<string, PolicyDecision> }>
  output_screening?: {
    flag_threshold?: number
    block_threshold?: number
    on_error?: 'flag' | 'block'
  }
}

const POLICY_SCHEMA = {
  type: 'object',
  required: ['roles'],
  additionalProperties: false,
  properties: {
    output_screening: {
      type: 'object',
      additionalProperties: false,
      properties: {
        flag_threshold: { type: 'number', minimum: 0, maximum: 1 },
        block_threshold: { type: 'number', minimum: 0, maximum: 1 },
        on_error: { enum: ['flag', 'block'] },
      },
    },
    roles: {
      type: 'object',
      additionalProperties: {
        type: 'object',
        required: ['tools'],
        additionalProperties: false,
        properties: {
          tools: {
            type: 'object',
            additionalProperties: { enum: [...POLICY_DECISIONS] },
          },
        },
      },
    },
  },
}

const validatePolicy = new Ajv({ allErrors: true }).compile<Policy>(POLICY_SCHEMA)

/** Throws on anything it cannot fully understand, so a bad policy stops the gateway. */
export function parsePolicy(source: string): Policy {
  let document: unknown
  try {
    document = parseYaml(source)
  } catch (error) {
    throw new Error(`policy is not valid YAML: ${String(error)}`)
  }
  if (!validatePolicy(document)) {
    throw new Error(`policy is malformed: ${new Ajv().errorsText(validatePolicy.errors)}`)
  }
  return document
}

export function loadPolicy(filePath: string): Policy {
  let source: string
  try {
    source = readFileSync(filePath, 'utf8')
  } catch (error) {
    throw new Error(`policy file "${filePath}" could not be read: ${String(error)}`)
  }
  return parsePolicy(source)
}

/** Output-screening thresholds are policy, not code, so they can be tuned per deployment. */
export function screeningConfig(policy: Policy): ScreeningConfig {
  const configured = policy.output_screening ?? {}
  return {
    flagThreshold: configured.flag_threshold ?? DEFAULT_SCREENING_CONFIG.flagThreshold,
    blockThreshold: configured.block_threshold ?? DEFAULT_SCREENING_CONFIG.blockThreshold,
    onError: configured.on_error ?? DEFAULT_SCREENING_CONFIG.onError,
  }
}

export type AuthorizationDecision =
  | { decision: 'auto'; effect: ToolEffect }
  | { decision: 'approve'; effect: ToolEffect }
  | { decision: 'deny'; code: AegisErrorCode; reason: string }

/** Fail-closed: only an explicit `auto` or `approve` entry lets a call proceed. */
export function authorize(
  policy: Policy,
  identity: CallerIdentity | null,
  toolName: string,
): AuthorizationDecision {
  if (!identity) {
    return {
      decision: 'deny',
      code: 'UNAUTHORIZED_CALLER',
      reason: 'no caller identity on the request',
    }
  }

  const effect = effectOf(toolName)
  if (!effect) {
    return { decision: 'deny', code: 'TOOL_NOT_ALLOWED', reason: `unknown tool "${toolName}"` }
  }
  // Checked before the policy file: an operator cannot grant a denied capability.
  if (effect === 'DENIED') {
    return {
      decision: 'deny',
      code: 'TOOL_DENIED',
      reason: `tool "${toolName}" is denied for all callers`,
    }
  }

  const role = policy.roles[identity.role]
  if (!role) {
    return {
      decision: 'deny',
      code: 'UNAUTHORIZED_CALLER',
      reason: `role "${identity.role}" has no policy`,
    }
  }

  const decision = role.tools[toolName]
  if (decision === undefined || decision === 'deny') {
    return {
      decision: 'deny',
      code: 'TOOL_NOT_ALLOWED',
      reason: `role "${identity.role}" may not call "${toolName}"`,
    }
  }
  return { decision, effect }
}
