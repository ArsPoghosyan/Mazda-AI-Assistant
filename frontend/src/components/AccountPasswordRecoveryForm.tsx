import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { useAccountPasswordRecovery } from '../hooks/useAccountPasswordRecovery'
import TurnstileChallenge from './TurnstileChallenge'

type AccountPasswordRecoveryFormProps = {
  siteKey: string
  titleId?: string
  initialEmail?: string
  onClose: () => void
  onSignIn: (email: string) => void
  onAccepted: (email: string) => void
  onEnterCode: (email: string) => void
}

export default function AccountPasswordRecoveryForm({
  siteKey, titleId, initialEmail = '', onClose, onSignIn, onAccepted, onEnterCode,
}: AccountPasswordRecoveryFormProps) {
  const recovery = useAccountPasswordRecovery()
  const id = useId()
  const headingId = titleId ?? `${id}-title`
  const emailInput = useRef<HTMLInputElement>(null)
  const formElement = useRef<HTMLFormElement>(null)
  const proof = useRef<string | null>(null)
  const generation = useRef(0)
  const active = useRef(false)
  const submitting = useRef(false)
  const [verified, setVerified] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const loading = recovery.status === 'loading'
  const accepted = recovery.status === 'accepted'
  const disabled = !recovery.enabled || loading || accepted
  const message = recovery.enabled ? recovery.message : 'Password recovery is not available here yet.'

  useEffect(() => {
    active.current = true
    emailInput.current?.focus()
    return () => { active.current = false; proof.current = null }
  }, [])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (disabled || submitting.current || !proof.current || !event.currentTarget.reportValidity()) return
    const email = new FormData(event.currentTarget).get('email')
    if (typeof email !== 'string') return

    submitting.current = true
    const captchaToken = proof.current
    proof.current = null
    setVerified(false)
    generation.current += 1
    setAttempt(generation.current)
    try {
      const succeeded = await recovery.start({ email, captcha_token: captchaToken })
      if (succeeded && active.current) onAccepted(email)
    } finally {
      submitting.current = false
    }
  }

  return (
    <section aria-labelledby={headingId} className="w-full max-w-md rounded-panel border border-divider bg-surface p-2 min-[360px]:p-5 sm:p-6">
      <div className="flex items-center justify-between gap-4">
        <h2 id={headingId} className="text-xl font-semibold">Recover your password</h2>
        <button type="button" onClick={onClose} aria-label="Close password recovery" className="inline-flex min-h-11 items-center px-3 text-sm text-muted hover:text-foreground">Close</button>
      </div>
      <p id={`${id}-help`} className="mt-2 text-sm text-muted">Enter your email to request a recovery code.</p>
      <form ref={formElement} method="post" onSubmit={submit} aria-labelledby={headingId} aria-describedby={`${id}-help ${id}-status`} className="mt-6 space-y-5">
        <fieldset disabled={disabled} className="space-y-2">
          <legend className="sr-only">Password recovery details</legend>
          <label htmlFor={`${id}-email`} className="block text-sm font-medium">Email</label>
          <input ref={emailInput} id={`${id}-email`} name="email" type="email" defaultValue={initialEmail} autoComplete="username" autoCapitalize="none" spellCheck={false} required maxLength={320} className="min-h-11 w-full rounded-control border border-control-border bg-background px-3 py-2 text-base text-foreground disabled:opacity-60" />
        </fieldset>
        {recovery.enabled && !loading && !accepted && (
          <TurnstileChallenge key={attempt} siteKey={siteKey} action="account_password_recovery"
            onToken={(token) => {
              if (!active.current || attempt !== generation.current) return
              proof.current = token
              setVerified(true)
            }}
            onInvalidated={() => {
              if (!active.current || attempt !== generation.current) return
              proof.current = null
              setVerified(false)
            }} />
        )}
        <p id={`${id}-status`} role="status" aria-atomic="true" className={message ? 'text-sm text-muted' : 'sr-only'}>{message}</p>
        <button type="submit" disabled={disabled || !verified} aria-busy={loading} aria-describedby={`${id}-status`} className="inline-flex min-h-11 w-full items-center justify-center rounded-control bg-accent px-6 py-3 font-semibold text-on-accent enabled:hover:bg-accent-hover disabled:opacity-60">
          {loading ? 'Requesting…' : accepted ? 'Check your email' : 'Send recovery code'}
        </button>
      </form>
      {recovery.enabled && (
        <div className="mt-4 flex flex-col items-start gap-1 text-sm">
          <button type="button" disabled={disabled} onClick={() => {
            if (!disabled && !submitting.current && formElement.current?.reportValidity()) {
              submitting.current = true
              onEnterCode(emailInput.current?.value ?? '')
            }
          }} className="inline-flex min-h-11 items-center text-accent enabled:hover:text-accent-hover disabled:opacity-60">I already have a recovery code</button>
          <button type="button" disabled={disabled} onClick={() => {
            if (!disabled && !submitting.current) {
              submitting.current = true
              onSignIn(emailInput.current?.value ?? '')
            }
          }} className="inline-flex min-h-11 items-center text-accent enabled:hover:text-accent-hover disabled:opacity-60">Back to sign in</button>
        </div>
      )}
    </section>
  )
}
