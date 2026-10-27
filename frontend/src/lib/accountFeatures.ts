/** Build-time UI rollout only; API authorization and proxy gates remain separate. */
export function isAccountAuthEnabled(): boolean {
  return import.meta.env.DEV || import.meta.env.VITE_ACCOUNT_AUTH_ENABLED === 'true'
}
