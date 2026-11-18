export type CallerIdentity = {
  agent_id: string
  role: string
}

/**
 * Identity is asserted by the caller (HTTP headers, or env in stdio mode) and is not yet
 * authenticated; phase 10 adds that. What matters here is that it is derived from the
 * request itself, deterministically, and never inferred from model output.
 */
export function parseIdentity(agentId: unknown, role: unknown): CallerIdentity | null {
  if (typeof agentId !== 'string' || typeof role !== 'string') return null
  const trimmedAgentId = agentId.trim()
  const trimmedRole = role.trim()
  if (!trimmedAgentId || !trimmedRole) return null
  return { agent_id: trimmedAgentId, role: trimmedRole }
}
