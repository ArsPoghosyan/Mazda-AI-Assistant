import TermsOfServiceLink from './TermsOfServiceLink'

export default function PrivacyNotice() {
  return (
    <div className="min-h-dvh bg-background text-foreground">
      <title>Privacy Notice | Mazda AI Assistant</title>
      <a
        href="#privacy-content"
        className="sr-only rounded-control bg-accent px-4 py-2 text-on-accent focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50"
      >
        Skip to privacy notice
      </a>
      <header className="mx-auto max-w-3xl border-b border-divider px-6 py-5">
        <nav aria-label="Policy navigation" className="flex flex-wrap items-center gap-x-6">
          <a href="/" className="inline-flex min-h-11 items-center text-accent underline underline-offset-4 hover:text-accent-hover">
            Back to Mazda AI Assistant
          </a>
          <TermsOfServiceLink />
        </nav>
      </header>
      <main id="privacy-content" tabIndex={-1} className="mx-auto max-w-3xl px-6 py-10 leading-7">
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">Privacy Notice</h1>
        <p className="mt-3 text-sm text-muted">Last updated: <time dateTime="2026-10-26">26 October 2026</time></p>
        <p className="mt-6 rounded-panel border border-divider bg-surface p-4">
          This website is in development. Public account and guest access are not
          enabled. AI chat and conversation storage are not active; the chat
          preview is illustrative. Authentication details below describe the
          implemented development and testing flows.
        </p>

        <section aria-labelledby="privacy-operator" className="mt-8 space-y-3">
          <h2 id="privacy-operator" className="text-xl font-semibold">Who operates this website</h2>
          <p>
            Mazda AI Assistant at askm6.com is operated by Arsen Poghosyan in
            Yerevan, Armenia, for users worldwide. It is independent, unofficial
            and unaffiliated with Mazda.
          </p>
          <p>
            For privacy questions or requests, email{' '}
            <a href="mailto:arsenpoghosyan29@gmail.com" className="break-all text-accent underline underline-offset-4">
              arsenpoghosyan29@gmail.com
            </a>.
          </p>
        </section>

        <section aria-labelledby="privacy-information" className="mt-8 space-y-3">
          <h2 id="privacy-information" className="text-xl font-semibold">Information and purposes</h2>
          <p>
            Hosting and security services handle connection information, such as
            IP addresses, requested pages, browser information and request times,
            to deliver the website, limit abuse and investigate failures.
            Cloudflare Web Analytics measures visits and page performance.
          </p>
          <p>
            Email authentication sends your email, password and human-verification
            proof through our website servers to Supabase Auth. Confirmation and
            recovery flows also process verification codes and, when you reset a
            password, your new password. Supabase manages password authentication;
            the application database does not store plaintext passwords.
          </p>
          <p>
            Choosing Google sends the information needed to authenticate your
            selected account, including its email and identifiers, through Google
            and Supabase. The application uses a verified account identifier.
          </p>
          <p>
            The application stores account identifiers, session activity and
            expiry times, protected session credentials and temporary Google
            sign-in records. Abuse counters use a keyed IP fingerprint and
            request times. These records are pseudonymous, not anonymous.
            Emailing the privacy contact also sends your address and message
            through Gmail so the operator can respond.
          </p>
          <p>
            When account setup is enabled, accepting the Terms records the
            account identifier, Terms version and acceptance time. This records
            Terms agreement, not blanket consent to personal-data processing.
            These acceptance records are removed with the application account profile.
          </p>
        </section>

        <section aria-labelledby="privacy-cookies" className="mt-8 space-y-3">
          <h2 id="privacy-cookies" className="text-xl font-semibold">Cookies and verification</h2>
          <p>
            When used, account and guest session cookies remember the browser
            session. A temporary cookie binds Google sign-in to its originating
            browser. Email registration uses an encrypted, HttpOnly cookie for up to one
            hour to carry your Terms agreement through email confirmation and a
            matching sign-in; it is then cleared. It stores an email hash, the
            Terms revision and time, and a confirmed account identifier after
            verification, without passwords or provider tokens. If it expires,
            account setup asks you to agree again. Production session cookies use Secure and HttpOnly
            protections. Blocking or clearing cookies can prevent sign-in or
            remove access to the guest identity in that browser. Signing out
            ends the local session; it does not delete the account.
          </p>
          <p>
            Cloudflare Turnstile handles browser and challenge information for
            human verification. Cloudflare Web Analytics is also present on the
            website. These services have their own data-handling documentation.
          </p>
        </section>

        <section aria-labelledby="privacy-providers" className="mt-8 space-y-3">
          <h2 id="privacy-providers" className="text-xl font-semibold">Providers and locations</h2>
          <ul className="list-disc space-y-2 pl-6">
            <li>Cloudflare: frontend hosting, request forwarding, security, Turnstile and analytics.</li>
            <li>Render: backend hosting in Frankfurt, Germany.</li>
            <li>Supabase: database and authentication; the project region is Frankfurt, Germany.</li>
            <li>Google: optional Google sign-in and Gmail privacy correspondence.</li>
            <li>Resend: authentication-email delivery through Supabase.</li>
          </ul>
          <p>
            Providers may process information outside Armenia and your country,
            including in the United States. Frankfurt hosting does not establish
            EU-only processing for every provider. Resend&apos;s Ireland sending
            region does not mean its stored email data stays in Ireland.
          </p>
        </section>

        <section aria-labelledby="privacy-retention" className="mt-8 space-y-3">
          <h2 id="privacy-retention" className="text-xl font-semibold">Retention</h2>
          <ul className="list-disc space-y-2 pl-6">
            <li>Guest sessions: expire after 30 inactive days.</li>
            <li>Account sessions: expire after 7 inactive days, with a maximum lifetime of 30 days.</li>
            <li>Pending Google sign-in attempts: expire after 10 minutes.</li>
            <li>Account records: kept while needed to maintain the open account, with verified deletion requests handled manually.</li>
            <li>Detailed privacy-request emails and attachments: kept for up to 90 days after resolution.</li>
            <li>Minimal request-completion records: kept for up to 12 months after resolution.</li>
          </ul>
          <p>
            Expired sessions are rejected even before stored records are removed.
            Scheduled cleanup removes expired session, pending sign-in and abuse
            records in batches while the backend is running. Session expiry does
            not delete an account. Privacy correspondence and completion records
            are managed manually; they are removed sooner when no longer needed,
            subject to applicable obligations or a documented, reviewed exception.
          </p>
          <p>
            Provider logs, authentication records, email and backups have separate
            retention arrangements. Resend currently documents standard email/log
            retention of 30 days. Hosting-log retention depends on the provider
            and plan; the application&apos;s cleanup does not erase provider logs
            or guarantee immediate removal from every backup.
          </p>
        </section>

        <section aria-labelledby="privacy-requests" className="mt-8 space-y-3">
          <h2 id="privacy-requests" className="text-xl font-semibold">Questions and requests</h2>
          <p>
            Contact the email above to request information, access, correction or
            deletion. Requests are reviewed manually and may require proportionate
            identity verification. There is no self-service account-deletion
            control. Do not email passwords, session cookies or verification codes.
          </p>
          <p>
            Depending on applicable law, you may also have rights to object,
            restrict processing, obtain a copy, withdraw consent where it is used,
            or complain to a competent data-protection authority.
          </p>
        </section>

        <section aria-labelledby="privacy-changes" className="mt-8 space-y-3">
          <h2 id="privacy-changes" className="text-xl font-semibold">Changes and further information</h2>
          <p>
            This notice will be reviewed before public authentication or AI chat
            is introduced, including information about conversation storage and
            AI-provider processing when those features are added.
          </p>
          <ul className="list-disc space-y-2 pl-6">
            <li><a href="https://www.cloudflare.com/privacypolicy/" className="text-accent underline underline-offset-4">Cloudflare privacy information</a></li>
            <li><a href="https://render.com/privacy" className="text-accent underline underline-offset-4">Render privacy information</a></li>
            <li><a href="https://supabase.com/privacy" className="text-accent underline underline-offset-4">Supabase privacy information</a></li>
            <li><a href="https://policies.google.com/privacy" className="text-accent underline underline-offset-4">Google privacy information</a></li>
            <li><a href="https://resend.com/security" className="text-accent underline underline-offset-4">Resend security and retention information</a></li>
          </ul>
        </section>
      </main>
    </div>
  )
}
