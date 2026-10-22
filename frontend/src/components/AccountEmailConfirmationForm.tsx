import { useEffect, useId, useRef, type FormEvent } from 'react'
import { useAccountEmailConfirmation } from '../hooks/useAccountEmailConfirmation'

type AccountEmailConfirmationFormProps = {
  email: string
  titleId?: string
  onClose: () => void
  onSignIn: () => void
}

export default function AccountEmailConfirmationForm({
  email,
  titleId,
  onClose,
  onSignIn,
}: AccountEmailConfirmationFormProps) {
  const confirmation = useAccountEmailConfirmation()
  const id = useId()
  const headingId = titleId ?? `${id}-title`
  const codeInput = useRef<HTMLInputElement>(null)

  const loading = confirmation.status === 'loading'
  const confirmed = confirmation.status === 'confirmed'
  const fieldsDisabled = !confirmation.enabled || loading || confirmed

  useEffect(() => {
    codeInput.current?.focus()
  }, [])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (fieldsDisabled) return

    const form = event.currentTarget

    if (!form.reportValidity()) return

    const data = new FormData(form)
    const code = data.get('code')

    if (typeof code !== 'string') return

    if (codeInput.current) {
      codeInput.current.value = ''
    }

    await confirmation.start({ email, code })
  }

  return (
    <section
      aria-labelledby={headingId}
      className="w-full max-w-md rounded-panel border border-divider bg-surface p-2 min-[360px]:p-5 sm:p-6"
    >
      <div className="flex items-center justify-between gap-4">
        <h2 id={headingId} className="text-xl font-semibold">
          Confirm your email
        </h2>

        <button
          type="button"
          onClick={onClose}
          aria-label="Close email confirmation"
          className="inline-flex min-h-11 items-center px-3 text-sm text-muted hover:text-foreground"
        >
          Close
        </button>
      </div>

      <p id={`${id}-help`} className="mt-2 text-sm text-muted">
        Enter the verification code from your registration email.
      </p>

      <p className="mt-4 text-sm text-muted">
        Email:{' '}
        <span className="break-all text-foreground">{email}</span>
      </p>

      <form
        method="post"
        onSubmit={submit}
        aria-labelledby={headingId}
        aria-describedby={`${id}-help ${id}-status`}
        className="mt-6 space-y-5"
      >
        <fieldset disabled={fieldsDisabled} className="space-y-2">
          <legend className="sr-only">Email verification</legend>

          <label
            htmlFor={`${id}-code`}
            className="block text-sm font-medium"
          >
            Verification code
          </label>

          <input
            ref={codeInput}
            id={`${id}-code`}
            name="code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            autoCapitalize="none"
            spellCheck={false}
            required
            minLength={6}
            maxLength={10}
            pattern="[0-9]{6,10}"
            aria-describedby={`${id}-code-help`}
            className="min-h-11 w-full rounded-control border border-control-border bg-background px-3 py-2 text-base text-foreground disabled:opacity-60"
          />

          <p id={`${id}-code-help`} className="text-sm text-muted">
            Enter the full code, including any leading zeros.
          </p>
        </fieldset>

        <p
          id={`${id}-status`}
          role="status"
          aria-atomic="true"
          className="min-h-6 text-sm text-muted"
        >
          {!confirmation.enabled
            ? 'Email confirmation is not available here yet.'
            : confirmation.message || 'Enter your code to confirm your email.'}
        </p>

        {confirmed ? (
          <button
            type="button"
            onClick={onSignIn}
            className="inline-flex min-h-11 w-full items-center justify-center rounded-control bg-accent px-6 py-3 font-semibold text-on-accent hover:bg-accent-hover"
          >
            Continue to sign in
          </button>
        ) : (
          <button
            type="submit"
            disabled={fieldsDisabled}
            aria-busy={loading}
            aria-describedby={`${id}-status`}
            className="inline-flex min-h-11 w-full items-center justify-center rounded-control bg-accent px-6 py-3 font-semibold text-on-accent enabled:hover:bg-accent-hover disabled:opacity-60"
          >
            {loading ? 'Confirming…' : 'Confirm email'}
          </button>
        )}
      </form>
    </section>
  )
}