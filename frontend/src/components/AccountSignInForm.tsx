import {
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
} from 'react'
import type { AccountSessionResponse } from '../api/account'
import { useAccountSignIn } from '../hooks/useAccountSignIn'
import TurnstileChallenge from './TurnstileChallenge'

type AccountSignInFormProps = {
  siteKey: string
  titleId?: string
  initialEmail?: string
  onCreateAccount?: () => void
  onClose: () => void
  onSignedIn?: (session: AccountSessionResponse) => void
}

export default function AccountSignInForm({
  siteKey,
  titleId,
  initialEmail = '',
  onCreateAccount,
  onClose,
  onSignedIn,
}: AccountSignInFormProps) {
  const signIn = useAccountSignIn()
  const id = useId()
  const headingId = titleId ?? `${id}-title`
  const emailInput = useRef<HTMLInputElement>(null)
  const proof = useRef<string | null>(null)
  const generation = useRef(0)
  const active = useRef(false)

  const [verified, setVerified] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const [showPassword, setShowPassword] = useState(false)

  const loading = signIn.status === 'loading'
  const ready = signIn.status === 'ready'
  const fieldsDisabled = !signIn.enabled || loading || ready

  useEffect(() => {
    active.current = true
    emailInput.current?.focus()

    return () => {
      active.current = false
    }
  }, [])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (fieldsDisabled || !proof.current) return

    const form = event.currentTarget
    const data = new FormData(form)
    const email = data.get('email')
    const password = data.get('password')

    if (typeof email !== 'string' || typeof password !== 'string') return

    const captchaToken = proof.current

    // Consume this proof immediately, before React renders again.
    proof.current = null
    setVerified(false)

    generation.current += 1
    setAttempt(generation.current)
    setShowPassword(false)

    const passwordInput = form.elements.namedItem('password')

    if (passwordInput instanceof HTMLInputElement) {
      passwordInput.value = ''
    }

    const session = await signIn.start({
      email,
      password,
      captcha_token: captchaToken,
    })

    if (session && active.current) onSignedIn?.(session)
  }

  return (
    <section
      aria-labelledby={headingId}
      className="w-full max-w-md rounded-panel border border-divider bg-surface p-2 min-[360px]:p-5 sm:p-6"
    >
      <div className="flex items-center justify-between gap-4">
        <h2 id={headingId} className="text-xl font-semibold">
          Sign in
        </h2>

        <button
          type="button"
          onClick={onClose}
          aria-label="Close sign-in"
          className="inline-flex min-h-11 items-center px-3 text-sm text-muted hover:text-foreground"
        >
          Close
        </button>
      </div>

      <p id={`${id}-help`} className="mt-2 text-sm text-muted">
        Use your email and password to sign in.
      </p>

      <form
        method="post"
        onSubmit={submit}
        aria-labelledby={headingId}
        aria-describedby={`${id}-help ${id}-status`}
        className="mt-6 space-y-5"
      >
        <fieldset disabled={fieldsDisabled} className="space-y-5">
          <legend className="sr-only">Account credentials</legend>

          <div className="space-y-2">
            <label
              htmlFor={`${id}-email`}
              className="block text-sm font-medium"
            >
              Email
            </label>

            <input
              ref={emailInput}
              id={`${id}-email`}
              name="email"
              type="email"
              defaultValue={initialEmail}
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              required
              maxLength={320}
              className="min-h-11 w-full rounded-control border border-control-border bg-background px-3 py-2 text-base text-foreground disabled:opacity-60"
            />
          </div>

          <div className="space-y-2">
            <label
              htmlFor={`${id}-password`}
              className="block text-sm font-medium"
            >
              Password
            </label>

            <input
              id={`${id}-password`}
              name="password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="current-password"
              required
              maxLength={1024}
              className="min-h-11 w-full rounded-control border border-control-border bg-background px-3 py-2 text-base text-foreground disabled:opacity-60"
            />

            <button
              type="button"
              aria-controls={`${id}-password`}
              aria-pressed={showPassword}
              onClick={() => setShowPassword((current) => !current)}
              className="inline-flex min-h-11 items-center text-sm text-accent hover:text-accent-hover"
            >
              Show password
            </button>
          </div>
        </fieldset>

        {signIn.enabled && !loading && !ready && (
          <TurnstileChallenge
            key={attempt}
            siteKey={siteKey}
            action="account_sign_in"
            onToken={(token) => {
              if (attempt !== generation.current) return

              proof.current = token
              setVerified(true)
            }}
            onInvalidated={() => {
              if (attempt !== generation.current) return

              proof.current = null
              setVerified(false)
            }}
          />
        )}

        <p
          id={`${id}-status`}
          role="status"
          aria-atomic="true"
          className="min-h-6 text-sm text-muted"
        >
          {!signIn.enabled
            ? 'Account sign-in is not available here yet.'
            : signIn.message ||
              'Enter your details and complete human verification.'}
        </p>

        <button
          type="submit"
          disabled={fieldsDisabled || !verified}
          aria-busy={loading}
          aria-describedby={`${id}-status`}
          className="inline-flex min-h-11 w-full items-center justify-center rounded-control bg-accent px-6 py-3 font-semibold text-on-accent enabled:hover:bg-accent-hover disabled:opacity-60"
        >
          {loading ? 'Signing in…' : ready ? 'Signed in' : 'Sign in'}
        </button>
      </form>
      {signIn.enabled && onCreateAccount && (
        <p className="mt-4 text-sm text-muted">
          New here?{' '}
          <button
            type="button"
            onClick={onCreateAccount}
            disabled={fieldsDisabled}
            className="inline-flex min-h-11 items-center font-medium text-accent enabled:hover:text-accent-hover disabled:opacity-60"
          >
            Create account
          </button>
        </p>
      )}
    </section>
  )
}
