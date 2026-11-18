import { Ajv, type ValidateFunction } from 'ajv'
import ajvFormats from 'ajv-formats'

// ajv-formats is CommonJS whose `module.exports` is the plugin function itself, but its
// ESM-style typings make TypeScript resolve the import to the module namespace.
const addFormats = ajvFormats as unknown as (ajv: Ajv) => void

const ajv = new Ajv({ allErrors: true, strict: false })
addFormats(ajv)

const validators = new Map<string, ValidateFunction>()

export type ValidationResult = { valid: true } | { valid: false; reason: string }

/**
 * Validates arguments against the tool's published JSON Schema. Values are never coerced:
 * a request that does not already match the schema is rejected.
 */
export function validateArguments(
  toolName: string,
  schema: Record<string, unknown>,
  args: Record<string, unknown>,
): ValidationResult {
  // The schemas Aegis fronts declare every accepted argument, so anything else is refused
  // rather than forwarded: undeclared arguments are not covered by the schema at all.
  const properties = schema.properties as Record<string, unknown> | undefined
  if (properties && schema.additionalProperties !== true) {
    const undeclared = Object.keys(args).filter((key) => !(key in properties))
    if (undeclared.length > 0) {
      return { valid: false, reason: `undeclared argument(s): ${undeclared.join(', ')}` }
    }
  }

  let validate = validators.get(toolName)
  if (!validate) {
    validate = ajv.compile(schema)
    validators.set(toolName, validate)
  }
  if (validate(args)) return { valid: true }
  return { valid: false, reason: ajv.errorsText(validate.errors, { dataVar: 'arguments' }) }
}
