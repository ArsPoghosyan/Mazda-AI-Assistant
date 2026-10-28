import PrivacyNoticeLink from './PrivacyNoticeLink'

export default function TermsOfService() {
  return (
    <div className="min-h-dvh bg-background text-foreground">
      <title>Terms of Service | askm6</title>
      <a
        href="#terms-content"
        className="sr-only rounded-control bg-accent px-4 py-2 text-on-accent focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50"
      >
        Skip to terms of service
      </a>
      <header className="mx-auto max-w-3xl border-b border-divider px-6 py-5">
        <nav aria-label="Policy navigation" className="flex flex-wrap items-center gap-x-6">
          <a href="/" className="inline-flex min-h-11 items-center text-accent underline underline-offset-4 hover:text-accent-hover">
            Back to askm6
          </a>
          <PrivacyNoticeLink />
        </nav>
      </header>
      <main id="terms-content" tabIndex={-1} className="mx-auto max-w-3xl px-6 py-10 leading-7">
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">Terms of Service</h1>
        <p className="mt-3 text-sm text-muted">Last updated: <time dateTime="2026-10-28">28 October 2026</time></p>

        <section aria-labelledby="terms-project" className="mt-8 space-y-3">
          <h2 id="terms-project" className="text-xl font-semibold">About this project</h2>
          <p>
            These terms describe the current development-stage website at
            askm6.com, operated by Arsen Poghosyan in Yerevan, Armenia.
            askm6 is independent, unofficial and unaffiliated
            with Mazda.
          </p>
        </section>

        <section aria-labelledby="terms-availability" className="mt-8 space-y-3">
          <h2 id="terms-availability" className="text-xl font-semibold">Current availability</h2>
          <p>
            Guest sessions and optional account registration, sign-in and
            password recovery are supported. AI chat,
            conversation storage and vehicle guidance are not active; the chat
            preview is illustrative.
          </p>
          <p>
            Features may change, pause or become unavailable during development.
            Continuous availability is not promised. This version offers no
            purchases or subscriptions.
          </p>
        </section>

        <section aria-labelledby="terms-responsible-use" className="mt-8 space-y-3">
          <h2 id="terms-responsible-use" className="text-xl font-semibold">Responsible use</h2>
          <p>
            Use the website lawfully. Do not attempt to access another person&apos;s
            account or data, bypass access controls or human verification, send
            malicious requests, or interfere with the service through abusive
            traffic. Report security concerns using the contact below.
          </p>
        </section>

        <section aria-labelledby="terms-account" className="mt-8 space-y-3">
          <h2 id="terms-account" className="text-xl font-semibold">Account security and requests</h2>
          <p>
            When creating or signing in to an account, use an email or Google account
            you control and keep your credentials private. Sign out on shared
            devices. Signing out ends the local session; it does not delete the
            account. Account-deletion requests are handled manually through the
            contact below; there is no self-service deletion control.
          </p>
          <p>
            Do not send passwords, verification codes or session cookies by email.
            Requests involving account information may require proportionate
            identity verification.
          </p>
        </section>

        <section aria-labelledby="terms-vehicle-information" className="mt-8 space-y-3">
          <h2 id="terms-vehicle-information" className="text-xl font-semibold">Vehicle information</h2>
          <p>
            The current website does not generate automotive advice or diagnose
            vehicle faults. It is not an emergency service. Use the appropriate
            vehicle documentation and qualified professional assistance for
            vehicle safety and repair decisions.
          </p>
        </section>

        <section aria-labelledby="terms-privacy" className="mt-8 space-y-3">
          <h2 id="terms-privacy" className="text-xl font-semibold">Privacy and changes</h2>
          <p>
            The <a href="/privacy" className="text-accent underline underline-offset-4">Privacy Notice</a>{' '}
            explains information handling, cookies, providers and retention.
            These terms will be reviewed before AI chat
            is introduced. Updated versions will show their revision date.
            Nothing here is intended to remove rights or protections that apply
            under applicable law.
          </p>
        </section>

        <section aria-labelledby="terms-contact" className="mt-8 space-y-3">
          <h2 id="terms-contact" className="text-xl font-semibold">Contact</h2>
          <p>
            Questions, privacy requests and security concerns can be sent to{' '}
            <a href="mailto:arsenpoghosyan29@gmail.com" className="break-all text-accent underline underline-offset-4">
              arsenpoghosyan29@gmail.com
            </a>.
          </p>
        </section>
      </main>
    </div>
  )
}
