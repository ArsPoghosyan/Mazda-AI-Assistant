import { useState } from 'react'
import type { AccountSessionResponse } from '../api/account'
import AccountEmailConfirmationForm from './AccountEmailConfirmationForm'
import AccountSignInForm from './AccountSignInForm'
import AccountSignUpForm from './AccountSignUpForm'

type AccountAccessFlowProps = {
  siteKey: string
  titleId: string
  onClose: () => void
  onSignedIn?: (session: AccountSessionResponse) => void
}

type AccessStep =
  | { mode: 'sign_in'; email: string }
  | { mode: 'sign_up' }
  | { mode: 'confirm_email'; email: string }

export default function AccountAccessFlow({
  siteKey,
  titleId,
  onClose,
  onSignedIn,
}: AccountAccessFlowProps) {
  const [step, setStep] = useState<AccessStep>({
    mode: 'sign_in',
    email: '',
  })

  if (step.mode === 'sign_up') {
    return (
      <AccountSignUpForm
        siteKey={siteKey}
        titleId={titleId}
        onClose={onClose}
        onSignIn={() => setStep({ mode: 'sign_in', email: '' })}
        onAccepted={(email) => setStep({ mode: 'confirm_email', email })}
      />
    )
  }

  if (step.mode === 'confirm_email') {
    return (
      <AccountEmailConfirmationForm
        email={step.email}
        titleId={titleId}
        onClose={onClose}
        onSignIn={() => setStep({ mode: 'sign_in', email: step.email })}
      />
    )
  }

  return (
    <AccountSignInForm
      siteKey={siteKey}
      titleId={titleId}
      initialEmail={step.email}
      onClose={onClose}
      onSignedIn={onSignedIn}
      onCreateAccount={() => setStep({ mode: 'sign_up' })}
    />
  )
}