import { useState } from 'react'
import type { AccountSessionResponse } from '../api/account'
import { isAccountRegistrationEnabled } from '../lib/accountFeatures'
import AccountEmailConfirmationForm from './AccountEmailConfirmationForm'
import AccountPasswordRecoveryForm from './AccountPasswordRecoveryForm'
import AccountPasswordResetForm from './AccountPasswordResetForm'
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
  | { mode: 'recover_password'; email: string }
  | { mode: 'reset_password'; email: string }

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

  if (step.mode === 'recover_password') {
    return (
      <AccountPasswordRecoveryForm
        siteKey={siteKey}
        titleId={titleId}
        initialEmail={step.email}
        onClose={onClose}
        onSignIn={(email) => setStep({ mode: 'sign_in', email })}
        onAccepted={(email) => setStep({ mode: 'reset_password', email })}
        onEnterCode={(email) => setStep({ mode: 'reset_password', email })}
      />
    )
  }

  if (step.mode === 'reset_password') {
    return (
      <AccountPasswordResetForm
        email={step.email}
        titleId={titleId}
        onClose={onClose}
        onSignIn={() => setStep({ mode: 'sign_in', email: step.email })}
        onRecover={() => setStep({ mode: 'recover_password', email: step.email })}
      />
    )
  }

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
      onCreateAccount={isAccountRegistrationEnabled()
        ? () => setStep({ mode: 'sign_up' })
        : undefined}
      onForgotPassword={import.meta.env.DEV
        ? (email) => setStep({ mode: 'recover_password', email })
        : undefined}
    />
  )
}
