import type { ToolEffect } from '@aegis/shared-types'

/**
 * Effect classification is owned by the gateway in code, deliberately not by policy YAML:
 * an operator editing policy must not be able to reclassify an irreversible tool, and the
 * MCP server's own annotations and `_meta` are never consulted. A tool that is absent here
 * is unknown to Aegis and refused.
 */
const TOOL_EFFECTS: Readonly<Record<string, ToolEffect>> = {
  get_payment_status: 'READ_ONLY',
  get_github_issue: 'READ_ONLY',
  github_create_issue: 'WRITE_IRREVERSIBLE',
  send_email: 'WRITE_IRREVERSIBLE',
  delete_repository: 'DENIED',
}

export function effectOf(toolName: string): ToolEffect | undefined {
  return TOOL_EFFECTS[toolName]
}

export function classifiedTools(): readonly string[] {
  return Object.keys(TOOL_EFFECTS)
}
