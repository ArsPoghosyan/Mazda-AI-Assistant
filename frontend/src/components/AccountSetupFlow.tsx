import { useId, useRef, useState } from 'react'
import type { AccountSessionResponse } from '../api/account'
import { useAccountSetup } from '../hooks/useAccountSetup'
import AccountDialog from './AccountDialog'
import PrivacyNoticeLink from './PrivacyNoticeLink'
import TermsOfServiceLink from './TermsOfServiceLink'

type Props = { session: AccountSessionResponse; onSessionExpired: () => void }

export default function AccountSetupFlow({ session, onSessionExpired }: Props) {
  const setup = useAccountSetup(session)
  const id = useId()
  const trigger = useRef<HTMLButtonElement>(null)
  const feedback = useRef<HTMLParagraphElement>(null)
  const [dismissed, setDismissed] = useState(false)
  const [agreed, setAgreed] = useState(false)
  const required = setup.status === 'required' || setup.status === 'submitting'
  const busy = setup.status === 'submitting'
  const buttonStyle = 'inline-flex min-h-11 items-center justify-center rounded-control border border-control-border px-6 py-3 font-medium text-foreground enabled:hover:bg-surface-raised disabled:opacity-60'

  return <>
    <div className={setup.status === 'ready' || setup.status === 'checking' || (required && !dismissed) ? 'sr-only' : 'basis-full space-y-2'}>
      <p ref={feedback} tabIndex={-1} role="status" aria-atomic="true" className="text-sm text-muted">
        {setup.status === 'ready' ? 'Account setup complete.' : setup.status === 'checking' ? 'Checking account setup…' : setup.status === 'expired'
          ? setup.message : required
            ? 'Finish account setup before using account features.' : setup.message}
      </p>
      {required && <button ref={trigger} type="button" className={buttonStyle}
        aria-haspopup="dialog" aria-controls={`${id}-dialog`} aria-expanded={!dismissed}
        onClick={() => setDismissed(false)}>Finish account setup</button>}
      {setup.status === 'unavailable' && <button type="button" className={buttonStyle} onClick={setup.retry}>Retry account setup</button>}
      {setup.status === 'expired' && <button type="button" className={buttonStyle} onClick={onSessionExpired}>Check account session</button>}
    </div>
    <AccountDialog id={`${id}-dialog`} titleId={`${id}-title`} open={required && !dismissed}
      onClose={() => setDismissed(true)} returnFocusRef={trigger} fallbackFocusRef={feedback}>
      <section className="w-full rounded-panel border border-divider bg-surface p-5 sm:p-6">
        <div className="flex items-center justify-between gap-4">
          <h2 id={`${id}-title`} tabIndex={-1} data-dialog-initial-focus className="text-xl font-semibold">Finish account setup</h2>
          <button type="button" className="inline-flex min-h-11 items-center px-3 text-sm text-muted hover:text-foreground"
            onClick={() => setDismissed(true)}>Close</button>
        </div>
        <p className="mt-3 text-sm text-muted">Review the Terms before using your account. You can sign out without completing setup.</p>
        <form className="mt-5 space-y-4" onSubmit={event => { event.preventDefault(); if (agreed && !busy) void setup.accept() }}>
          <div className="flex flex-wrap gap-x-4 text-sm"><PrivacyNoticeLink newTab /></div>
          <div className="flex min-h-11 items-center gap-3 text-sm">
            <input type="checkbox" aria-labelledby={`${id}-agreement`} checked={agreed} disabled={busy} onChange={event => setAgreed(event.target.checked)}
              className="h-5 w-5 shrink-0 accent-accent" />
            <span id={`${id}-agreement`}>I agree to the <TermsOfServiceLink newTab />.</span>
          </div>
          <p id={`${id}-message`} role="status" aria-atomic="true" className={setup.message ? 'text-sm text-muted' : 'sr-only'}>{setup.message}</p>
          <button type="submit" disabled={!agreed || busy} aria-busy={busy} aria-describedby={`${id}-message`}
            className="inline-flex min-h-11 w-full items-center justify-center rounded-control bg-accent px-6 py-3 font-semibold text-on-accent enabled:hover:bg-accent-hover disabled:opacity-60">
            {busy ? 'Finishing setup…' : 'Finish setup'}
          </button>
        </form>
      </section>
    </AccountDialog>
  </>
}
