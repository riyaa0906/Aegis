/**
 * Screens tool output for indirect prompt injection.
 *
 * The classifier is one layer, not the security boundary: it is imperfect by nature, so a
 * clean score never grants authority. Authorization, effect classification and approval
 * stay deterministic, and every screened result is still labelled untrusted.
 */

export type ScreeningStatus = 'clean' | 'suspicious' | 'high_risk' | 'unavailable' | 'disabled'
export type ScreeningAction = 'allow' | 'flag' | 'block'

export type ScreeningResult = {
  status: ScreeningStatus
  action: ScreeningAction
  /** Probability that the output contains an injection, or null when unscreened. */
  score: number | null
  detail?: string
}

export type ScreeningConfig = {
  flagThreshold: number
  blockThreshold: number
  /** What to do when the classifier is configured but cannot be reached. */
  onError: ScreeningAction & ('flag' | 'block')
}

/**
 * Starting points only. Phase 9 tunes them against the red-team and benign datasets;
 * they are not claimed to be optimal.
 */
export const DEFAULT_SCREENING_CONFIG: ScreeningConfig = {
  flagThreshold: 0.5,
  blockThreshold: 0.9,
  onError: 'block',
}

/** Returns the probability that `text` contains a prompt injection. */
export type Classifier = (text: string) => Promise<number>

export function createHttpClassifier(url: string, timeoutMs = 5_000): Classifier {
  return async (text) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text }),
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (!response.ok) throw new Error(`classifier responded ${response.status}`)
    const body = (await response.json()) as { score?: unknown }
    if (typeof body.score !== 'number') throw new Error('classifier returned no score')
    return body.score
  }
}

export async function screenOutput(
  text: string,
  classifier: Classifier | null | undefined,
  config: ScreeningConfig,
): Promise<ScreeningResult> {
  if (!classifier) return { status: 'disabled', action: 'allow', score: null }

  let score: number
  try {
    score = await classifier(text)
  } catch (error) {
    return {
      status: 'unavailable',
      action: config.onError,
      score: null,
      detail: `classifier unavailable: ${String(error)}`,
    }
  }

  if (score >= config.blockThreshold) return { status: 'high_risk', action: 'block', score }
  if (score >= config.flagThreshold) return { status: 'suspicious', action: 'flag', score }
  return { status: 'clean', action: 'allow', score }
}
