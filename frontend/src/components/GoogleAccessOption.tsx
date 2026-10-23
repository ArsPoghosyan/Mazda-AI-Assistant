import googleIcon from '../assets/google-g.png'

type GoogleAccessOptionProps = {
  statusId: string
  disabled: boolean
  busy: boolean
  message: string
  onContinue: () => void
}

export default function GoogleAccessOption({
  statusId,
  disabled,
  busy,
  message,
  onContinue,
}: GoogleAccessOptionProps) {
  return (
    <div className="mt-6">
      <button
        type="button"
        disabled={disabled}
        aria-busy={busy}
        aria-describedby={statusId}
        onClick={onContinue}
        className="google-sign-in-button flex min-h-12 w-full items-center justify-center gap-2.5 rounded-control border px-3 py-3 text-sm font-medium leading-5 disabled:opacity-60"
      >
        <img src={googleIcon} width={20} height={20} alt="" aria-hidden="true" className="h-5 w-5 shrink-0 object-contain" />
        <span>Continue with Google</span>
      </button>
      <p
        id={statusId}
        role="status"
        aria-atomic="true"
        className={message ? 'mt-3 text-sm text-muted' : 'sr-only'}
      >
        {message}
      </p>
      <div aria-hidden="true" className="mt-6 flex items-center gap-3 text-sm text-muted">
        <span className="h-px flex-1 bg-divider" />
        <span>or use email</span>
        <span className="h-px flex-1 bg-divider" />
      </div>
    </div>
  )
}
