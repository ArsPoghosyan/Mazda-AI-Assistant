/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_TURNSTILE_SITE_KEY?: string
  readonly VITE_GOOGLE_OAUTH_ENABLED?: string
  readonly VITE_SUPABASE_AUTH_ISSUER?: string
}