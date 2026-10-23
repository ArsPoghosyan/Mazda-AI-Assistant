import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { useAccountPasswordReset } from '../hooks/useAccountPasswordReset'

type AccountPasswordResetFormProps = {
  email: string
  titleId?: string
  onClose: () => void
  onSignIn: () => void
  onRecover: () => void
}

export default function AccountPasswordResetForm({
  email, titleId, onClose, onSignIn, onRecover,
}: AccountPasswordResetFormProps) {
  const reset = useAccountPasswordReset()
  const id = useId()
  const headingId = titleId ?? `${id}-title`
  const codeInput = useRef<HTMLInputElement>(null)
  const passwordInput = useRef<HTMLInputElement>(null)
  const continueButton = useRef<HTMLButtonElement>(null)
  const submitting = useRef(false)
  const [showPassword, setShowPassword] = useState(false)
  const loading = reset.status === 'loading'
  const completed = reset.status === 'completed'
  const disabled = !reset.enabled || loading || completed
  const message = reset.enabled ? reset.message : 'Password reset is not available here yet.'

  useEffect(() => {
    const code = codeInput.current
    const password = passwordInput.current
    code?.focus()
    return () => {
      if (code) code.value = ''
      if (password) password.value = ''
    }
  }, [])
  useEffect(() => {
    if (completed) continueButton.current?.focus()
    else if (reset.status === 'error') codeInput.current?.focus()
  }, [completed, reset.status])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (disabled || submitting.current || !event.currentTarget.reportValidity()) return
    const data = new FormData(event.currentTarget)
    const code = data.get('code')
    const newPassword = data.get('new_password')
    if (typeof code !== 'string' || typeof newPassword !== 'string') return

    submitting.current = true
    if (codeInput.current) codeInput.current.value = ''
    if (passwordInput.current) passwordInput.current.value = ''
    setShowPassword(false)
    try {
      await reset.start({ email, code, new_password: newPassword })
    } finally {
      submitting.current = false
    }
  }

  function returnToSignIn() {
    if (reset.enabled && !loading && !submitting.current) {
      submitting.current = true
      onSignIn()
    }
  }

  return (
    <section aria-labelledby={headingId} className="w-full max-w-md rounded-panel border border-divider bg-surface p-2 min-[360px]:p-5 sm:p-6">
      <div className="flex items-center justify-between gap-4">
        <h2 id={headingId} className="text-xl font-semibold">Reset your password</h2>
        <button type="button" onClick={onClose} aria-label="Close password reset" className="inline-flex min-h-11 items-center px-3 text-sm text-muted hover:text-foreground">Close</button>
      </div>
      <p id={`${id}-help`} className="mt-2 text-sm text-muted">If password recovery can proceed, check your email for the recovery code. Enter it below and choose a new password.</p>
      <p className="mt-4 text-sm text-muted">Email: <span className="break-all text-foreground">{email}</span></p>
      <form method="post" onSubmit={submit} aria-labelledby={headingId} aria-describedby={`${id}-help ${id}-status`} className="mt-6 space-y-5">
        <fieldset disabled={disabled} className="space-y-5">
          <legend className="sr-only">Password reset details</legend>
          <div className="space-y-2">
            <label htmlFor={`${id}-code`} className="block text-sm font-medium">Recovery code</label>
            <input ref={codeInput} id={`${id}-code`} name="code" type="text" inputMode="numeric" autoComplete="one-time-code" autoCapitalize="none" spellCheck={false} required minLength={6} maxLength={10} pattern="[0-9]{6,10}" aria-describedby={`${id}-code-help`} className="min-h-11 w-full rounded-control border border-control-border bg-background px-3 py-2 text-base text-foreground disabled:opacity-60" />
            <p id={`${id}-code-help`} className="text-sm text-muted">Enter the full code, including any leading zeros.</p>
          </div>
          <div className="space-y-2">
            <label htmlFor={`${id}-password`} className="block text-sm font-medium">New password</label>
            <input ref={passwordInput} id={`${id}-password`} name="new_password" type={showPassword ? 'text' : 'password'} autoComplete="new-password" required maxLength={1024} className="min-h-11 w-full rounded-control border border-control-border bg-background px-3 py-2 text-base text-foreground disabled:opacity-60" />
            <button type="button" aria-controls={`${id}-password`} aria-pressed={showPassword} onClick={() => setShowPassword((current) => !current)} className="inline-flex min-h-11 items-center text-sm text-accent hover:text-accent-hover">Show password</button>
          </div>
        </fieldset>
        <p id={`${id}-status`} role="status" aria-atomic="true" className={message ? 'text-sm text-muted' : 'sr-only'}>{message}</p>
        {completed ? (
          <button ref={continueButton} type="button" onClick={returnToSignIn} className="inline-flex min-h-11 w-full items-center justify-center rounded-control bg-accent px-6 py-3 font-semibold text-on-accent hover:bg-accent-hover">Continue to sign in</button>
        ) : (
          <button type="submit" disabled={disabled} aria-busy={loading} aria-describedby={`${id}-status`} className="inline-flex min-h-11 w-full items-center justify-center rounded-control bg-accent px-6 py-3 font-semibold text-on-accent enabled:hover:bg-accent-hover disabled:opacity-60">{loading ? 'Resetting…' : 'Reset password'}</button>
        )}
      </form>
      {reset.enabled && !completed && (
        <div className="mt-4 flex flex-col items-start gap-1 text-sm">
          <button type="button" disabled={loading} onClick={returnToSignIn} className="inline-flex min-h-11 items-center text-accent enabled:hover:text-accent-hover disabled:opacity-60">Back to sign in</button>
          <button type="button" disabled={loading} onClick={() => {
            if (!loading && !submitting.current) {
              submitting.current = true
              onRecover()
            }
          }} className="inline-flex min-h-11 items-center text-accent enabled:hover:text-accent-hover disabled:opacity-60">Request another code</button>
        </div>
      )}
    </section>
  )
}
