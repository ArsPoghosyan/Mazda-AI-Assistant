import { useEffect, useRef, type ReactNode, type RefObject } from 'react'

type Props = {
  id: string
  titleId: string
  open: boolean
  onClose: () => void
  returnFocusRef: RefObject<HTMLElement | null>
  fallbackFocusRef?: RefObject<HTMLElement | null>
  initialFocus?: string
  children: ReactNode
}

export default function AccountDialog({ id, titleId, open, onClose, returnFocusRef,
  fallbackFocusRef, initialFocus = '[data-dialog-initial-focus]', children }: Props) {
  const dialog = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const element = dialog.current
    if (!open || !element) return
    const returnFocus = returnFocusRef.current
    const fallbackFocus = fallbackFocusRef?.current
    element.showModal()
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    element.querySelector<HTMLElement>(initialFocus)?.focus()
    return () => {
      if (element.open) element.close()
      document.body.style.overflow = previousOverflow
      const target = returnFocus?.isConnected && !returnFocus.matches(':disabled') ? returnFocus : fallbackFocus
      target?.focus()
    }
  }, [open, returnFocusRef, fallbackFocusRef, initialFocus])

  function focusEdge(edge: 'first' | 'last') {
    const controls = Array.from(dialog.current?.querySelectorAll<HTMLElement>(
      'button, input:not([type="hidden"]), select, textarea, a[href], iframe, [tabindex]',
    ) ?? []).filter(element => !element.hasAttribute('data-dialog-focus-guard') &&
      element.tabIndex >= 0 && !element.matches(':disabled') && element.getClientRects().length > 0)
    const target = edge === 'first' ? controls[0] : controls.at(-1)
    target?.focus()
  }

  return <dialog ref={dialog} id={id} aria-labelledby={titleId} aria-modal="true"
    onCancel={event => { event.preventDefault(); onClose() }}
    className="sign-in-dialog fixed inset-0 m-auto max-h-[calc(100dvh-2rem)] w-full max-w-md overflow-y-auto rounded-panel border-0 bg-surface p-0 text-foreground">
    <span tabIndex={0} aria-hidden="true" data-dialog-focus-guard className="sr-only" onFocus={() => focusEdge('last')} />
    {open && children}
    <span tabIndex={0} aria-hidden="true" data-dialog-focus-guard className="sr-only" onFocus={() => focusEdge('first')} />
  </dialog>
}
