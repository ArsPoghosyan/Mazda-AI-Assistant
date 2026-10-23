export type GoogleReturnOutcome =
  | 'success'
  | 'rejected'
  | 'unavailable'
  | 'sign-out-required'

export function parseGoogleReturn(
  hash: string,
): GoogleReturnOutcome | null {
  switch (hash) {
    case '#google-sign-in=success':
      return 'success'
    case '#google-sign-in=rejected':
      return 'rejected'
    case '#google-sign-in=unavailable':
      return 'unavailable'
    case '#google-sign-in=sign-out-required':
      return 'sign-out-required'
    default:
      return null
  }
}

export function consumeGoogleReturn(): GoogleReturnOutcome | null {
  const outcome = parseGoogleReturn(window.location.hash)
  if (outcome === null) return null

  try {
    window.history.replaceState(
      window.history.state,
      '',
      window.location.pathname + window.location.search,
    )
  } catch {
    return null
  }

  return outcome
}
