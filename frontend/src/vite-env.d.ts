/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_GUEST_ACCESS_ENABLED?: string
  readonly VITE_ACCOUNT_AUTH_ENABLED?: string
  readonly VITE_ACCOUNT_REGISTRATION_ENABLED?: string
  readonly VITE_ACCOUNT_RECOVERY_ENABLED?: string
  readonly VITE_TURNSTILE_SITE_KEY?: string
  readonly VITE_GOOGLE_OAUTH_ENABLED?: string
  readonly VITE_SUPABASE_AUTH_ISSUER?: string
}
