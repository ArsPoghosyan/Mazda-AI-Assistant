/** Build-time UI rollout only; API authorization and proxy gates remain separate. */
export function isAccountAuthEnabled(): boolean {
  return import.meta.env.DEV || import.meta.env.VITE_ACCOUNT_AUTH_ENABLED === 'true'
}

/** Sign-up and code confirmation are one rollout; a separate sign-in is required. */
export function isAccountRegistrationEnabled(): boolean {
  return isAccountAuthEnabled() &&
    (import.meta.env.DEV || import.meta.env.VITE_ACCOUNT_REGISTRATION_ENABLED === 'true')
}
