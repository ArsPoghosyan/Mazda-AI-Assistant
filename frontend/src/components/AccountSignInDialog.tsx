import { useEffect, useId, useRef, type RefObject } from 'react'
import type { AccountSessionResponse } from '../api/account'
import AccountAccessFlow from './AccountAccessFlow'

type AccountSignInDialogProps = {
  open: boolean
  siteKey: string
  onClose: () => void
  returnFocusRef: RefObject<HTMLButtonElement | null>
  fallbackFocusRef?: RefObject<HTMLElement | null>
  onSignedIn?: (session: AccountSessionResponse) => void
}

export default function AccountSignInDialog({
  open,
  siteKey,
  onClose,
  returnFocusRef,
  fallbackFocusRef,
  onSignedIn,
}: AccountSignInDialogProps) {
  const dialog = useRef<HTMLDialogElement>(null)
  const titleId = useId()

  useEffect(() => {
    const element = dialog.current
    if (!open || !element) return

    const returnFocus = returnFocusRef.current
    const fallbackFocus = fallbackFocusRef?.current
    element.showModal()
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    element.querySelector<HTMLInputElement>('input[type="email"]')?.focus()

    return () => {
      if (element.open) element.close()
      document.body.style.overflow = previousOverflow
      const target = returnFocus?.disabled
        ? fallbackFocus
        : returnFocus
      target?.focus()
    }
  }, [open, returnFocusRef, fallbackFocusRef])

  function focusEdge(edge: 'first' | 'last') {
    const controls = Array.from(
      dialog.current?.querySelectorAll<HTMLElement>(
        'button, input:not([type="hidden"]), select, textarea, a[href], iframe, [tabindex]',
      ) ?? [],
    ).filter((element) =>
      !element.hasAttribute('data-dialog-focus-guard') &&
      element.tabIndex >= 0 &&
      !element.matches(':disabled') &&
      element.getClientRects().length > 0,
    )

    const target = edge === 'first' ? controls[0] : controls.at(-1)
    target?.focus()
  }

  return (
    <dialog
      ref={dialog}
      id="account-sign-in-panel"
      aria-labelledby={titleId}
      aria-modal="true"
      onCancel={(event) => {
        event.preventDefault()
        onClose()
      }}
      className="sign-in-dialog fixed inset-0 m-auto max-h-[calc(100dvh-2rem)] w-full max-w-md overflow-y-auto rounded-panel border-0 bg-surface p-0 text-foreground"
    >
      {/* Guards also catch Tab leaving the verification iframe. */}
      <span
        tabIndex={0}
        aria-hidden="true"
        data-dialog-focus-guard
        className="sr-only"
        onFocus={() => focusEdge('last')}
      />
      {open && (
        <AccountAccessFlow
          siteKey={siteKey}
          titleId={titleId}
          onClose={onClose}
          onSignedIn={onSignedIn}
        />
      )}
      <span
        tabIndex={0}
        aria-hidden="true"
        data-dialog-focus-guard
        className="sr-only"
        onFocus={() => focusEdge('first')}
      />
    </dialog>
  )
}
