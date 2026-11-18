import { describe, expect, it } from 'vitest'
import { AEGIS_ERROR_CODES, POLICY_DECISIONS, TOOL_EFFECTS } from '@aegis/shared-types'

describe('security vocabulary', () => {
  it('exposes exactly the three effect classes', () => {
    expect([...TOOL_EFFECTS]).toEqual(['READ_ONLY', 'WRITE_IRREVERSIBLE', 'DENIED'])
  })

  it('exposes exactly the three policy decisions', () => {
    expect([...POLICY_DECISIONS]).toEqual(['auto', 'approve', 'deny'])
  })

  it('has no duplicate error codes', () => {
    expect(new Set(AEGIS_ERROR_CODES).size).toBe(AEGIS_ERROR_CODES.length)
  })
})
