/**
 * Security vocabulary shared by the gateway, the MCP server and the agent.
 * These values are fixed configuration: they are never derived from model output.
 */

/** How consequential a tool call is. Declared per tool, never inferred at runtime. */
export const TOOL_EFFECTS = ['READ_ONLY', 'WRITE_IRREVERSIBLE', 'DENIED'] as const
export type ToolEffect = (typeof TOOL_EFFECTS)[number]

/** Outcome of evaluating a caller's policy against a tool. */
export const POLICY_DECISIONS = ['auto', 'approve', 'deny'] as const
export type PolicyDecision = (typeof POLICY_DECISIONS)[number]

/** Structured failure reasons returned to callers. */
export const AEGIS_ERROR_CODES = [
  'UNAUTHORIZED_CALLER',
  'TOOL_NOT_ALLOWED',
  'INVALID_ARGUMENTS',
  'TOOL_DENIED',
  'APPROVAL_REQUIRED',
  'APPROVAL_REJECTED',
  'APPROVAL_TIMEOUT',
  'TOOL_EXECUTION_FAILED',
  'OUTPUT_SECURITY_BLOCKED',
  'MCP_CONNECTION_ERROR',
] as const
export type AegisErrorCode = (typeof AEGIS_ERROR_CODES)[number]
