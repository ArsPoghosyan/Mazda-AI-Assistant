import {
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
} from 'react'
import { useAccountSignUp } from '../hooks/useAccountSignUp'
import { useGoogleSignIn } from '../hooks/useGoogleSignIn'
import GoogleAccessOption from './GoogleAccessOption'
import PrivacyNoticeLink from './PrivacyNoticeLink'
import TermsOfServiceLink from './TermsOfServiceLink'
import TurnstileChallenge from './TurnstileChallenge'
import { CURRENT_TERMS_VERSION } from '../../shared/account-terms'

type AccountSignUpFormProps = {
  siteKey: string
  titleId?: string
  onClose: () => void
  onAccepted: (email: string) => void
  onSignIn?: () => void
}

export default function AccountSignUpForm({
  siteKey,
  titleId,
  onClose,
  onAccepted,
  onSignIn,
}: AccountSignUpFormProps) {
  const signUp = useAccountSignUp()
  const google = useGoogleSignIn()
  const id = useId()
  const headingId = titleId ?? `${id}-title`
  const emailInput = useRef<HTMLInputElement>(null)
  const proof = useRef<string | null>(null)
  const generation = useRef(0)
  const active = useRef(false)
  const formElement = useRef<HTMLFormElement>(null)
  const accessOperation = useRef<'email' | 'google' | null>(null)

  const [verified, setVerified] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const [showPassword, setShowPassword] = useState(false)
  const [agreed, setAgreed] = useState(false)

  const loading = signUp.status === 'loading'
  const accepted = signUp.status === 'accepted'
  const googleBusy = google.status === 'loading' || google.status === 'redirecting'
  const fieldsDisabled = !signUp.enabled || loading || accepted || googleBusy
  const statusMessage = googleBusy
    ? ''
    : !signUp.enabled
      ? 'Account registration is not available here yet.'
      : signUp.message

  useEffect(() => {
    active.current = true
    emailInput.current?.focus()

    return () => {
      active.current = false
    }
  }, [])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (fieldsDisabled || !agreed || !proof.current || accessOperation.current) return

    const form = event.currentTarget
    const data = new FormData(form)
    const email = data.get('email')
    const password = data.get('password')

    if (typeof email !== 'string' || typeof password !== 'string') return

    accessOperation.current = 'email'
    const captchaToken = proof.current

    // Consume the proof before another submit event can reuse it.
    proof.current = null
    setVerified(false)

    generation.current += 1
    setAttempt(generation.current)
    setShowPassword(false)

    const passwordInput = form.elements.namedItem('password')

    if (passwordInput instanceof HTMLInputElement) {
      passwordInput.value = ''
    }

    let completed = false
    try {
      completed = await signUp.start({
        email,
        password,
        captcha_token: captchaToken,
        accepted: true,
        terms_version: CURRENT_TERMS_VERSION,
      })

      if (completed && active.current) onAccepted(email)
    } finally {
      if (!completed && accessOperation.current === 'email') {
        accessOperation.current = null
      }
    }
  }

  async function startGoogle() {
    if (!google.enabled || loading || accepted || googleBusy || accessOperation.current) return

    accessOperation.current = 'google'
    proof.current = null
    setVerified(false)
    generation.current += 1
    setAttempt(generation.current)
    setShowPassword(false)

    const passwordInput = formElement.current?.elements.namedItem('password')
    if (passwordInput instanceof HTMLInputElement) passwordInput.value = ''

    try {
      await google.start()
    } finally {
      if (accessOperation.current === 'google') accessOperation.current = null
    }
  }

  return (
    <section
      aria-labelledby={headingId}
      className="w-full max-w-md rounded-panel border border-divider bg-surface p-2 min-[360px]:p-5 sm:p-6"
    >
      <div className="flex items-center justify-between gap-4">
        <h2 id={headingId} className="text-xl font-semibold">
          Create account
        </h2>

        <button
          type="button"
          onClick={onClose}
          aria-label="Close registration"
          className="inline-flex min-h-11 items-center px-3 text-sm text-muted hover:text-foreground"
        >
          Close
        </button>
      </div>

      <p id={`${id}-help`} className="mt-2 text-sm text-muted">
        {google.enabled
          ? 'Choose Google or use your email and a password. Email registration requires confirmation.'
          : 'Enter your email and choose a password. Confirm your email before signing in.'}
      </p>

      {google.enabled && (
        <GoogleAccessOption
          statusId={`${id}-google-status`}
          disabled={loading || accepted || googleBusy}
          busy={googleBusy}
          message={google.message}
          onContinue={() => { void startGoogle() }}
        />
      )}

      <form
        ref={formElement}
        method="post"
        onSubmit={submit}
        aria-labelledby={headingId}
        aria-describedby={`${id}-help ${id}-status`}
        className="mt-5 space-y-4"
      >
        <fieldset disabled={fieldsDisabled} className="space-y-5">
          <legend className="sr-only">Registration details</legend>

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
              autoComplete="new-password"
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

        {signUp.enabled && !loading && !accepted && !googleBusy && (
          <TurnstileChallenge
            key={attempt}
            siteKey={siteKey}
            action="account_sign_up"
            onToken={(token) => {
              if (!active.current || attempt !== generation.current) return

              proof.current = token
              setVerified(true)
            }}
            onInvalidated={() => {
              if (!active.current || attempt !== generation.current) return

              proof.current = null
              setVerified(false)
            }}
          />
        )}

        <div className="space-y-1">
          <div className="flex min-h-11 items-center gap-3 text-sm">
            <input
              type="checkbox"
              aria-labelledby={`${id}-agreement`}
              required
              checked={agreed}
              disabled={fieldsDisabled}
              onChange={event => setAgreed(event.target.checked)}
              className="h-5 w-5 shrink-0 accent-accent"
            />
            <span id={`${id}-agreement`}>I agree to the <TermsOfServiceLink newTab />.</span>
          </div>
          <p className="text-sm text-muted"><PrivacyNoticeLink newTab /></p>
          <p
            id={`${id}-status`}
            role="status"
            aria-atomic="true"
            className={statusMessage ? 'text-sm text-muted' : 'sr-only'}
          >
            {statusMessage}
          </p>
        </div>

        <button
          type="submit"
          disabled={fieldsDisabled || !verified || !agreed}
          aria-busy={loading}
          aria-describedby={`${id}-status`}
          className="inline-flex min-h-11 w-full items-center justify-center rounded-control bg-accent px-6 py-3 font-semibold text-on-accent enabled:hover:bg-accent-hover disabled:opacity-60"
        >
          {loading
            ? 'Submitting…'
            : accepted
              ? 'Check your email'
              : 'Create account'}
        </button>
      </form>
      {signUp.enabled && onSignIn && (
        <p className="mt-4 text-sm text-muted">
          Already have an account?{' '}
          <button
            type="button"
            onClick={() => {
              if (!fieldsDisabled && !accessOperation.current) onSignIn()
            }}
            disabled={fieldsDisabled}
            className="inline-flex min-h-11 items-center font-medium text-accent enabled:hover:text-accent-hover disabled:opacity-60"
          >
            Back to sign in
          </button>
        </p>
      )}
    </section>
  )
}
