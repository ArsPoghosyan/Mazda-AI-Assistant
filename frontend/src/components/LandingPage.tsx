import type { ReactNode } from 'react'
import PrivacyNoticeLink from './PrivacyNoticeLink'

type LandingPageProps = {
  guestAction: ReactNode
  accountAction: ReactNode
  accountPanel: ReactNode
  serviceStatus: ReactNode
}

const capabilities = [
  {
    title: 'Vehicle information',
    description: 'Information matched to the relevant year and vehicle variant.',
  },
  {
    title: 'Guided troubleshooting',
    description: 'Work through symptoms and useful follow-up questions.',
  },
  {
    title: 'Traceable references',
    description: 'Inspect the evidence behind supported answers.',
  },
]

export default function LandingPage({
  guestAction,
  accountAction,
  accountPanel,
  serviceStatus,
}: LandingPageProps) {
  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground">
      <a
        href="#main-content"
        className="sr-only rounded-control bg-accent px-4 py-2 text-on-accent focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50"
      >
        Skip to content
      </a>

      <header className="mx-auto flex w-full max-w-7xl items-center justify-between border-b border-divider px-6 py-6 lg:px-10">
        <a href="/" aria-label="askm6 home" className="text-2xl font-semibold">
          askm6
        </a>

        <nav aria-label="Main navigation">
          <a
            href="#about"
            className="inline-flex min-h-11 items-center px-3 text-sm text-muted hover:text-foreground"
          >
            About
          </a>
        </nav>
      </header>

      <main
        id="main-content"
        tabIndex={-1}
        className="mx-auto w-full max-w-7xl flex-1 px-2 min-[360px]:px-6 lg:px-10"
      >
        <section
          aria-labelledby="landing-title"
          className="grid gap-10 py-12 lg:grid-cols-2 lg:items-center lg:gap-14 lg:py-20"
        >
          <div>
            <h1
              id="landing-title"
              className="max-w-[19ch] text-4xl leading-tight font-semibold tracking-tight text-balance sm:text-5xl"
            >
              Understand your Mazda. Know where the answer comes from.
            </h1>

            <p className="mt-6 max-w-lg text-lg leading-relaxed text-muted">
              An assistant in development for Mazda maintenance questions,
              warning lights and vehicle information, with references you can
              inspect.
            </p>

            <p className="mt-3 max-w-lg text-sm text-muted">
              Initial vehicle support is planned for Mazda&nbsp;6.
            </p>

            <div className="mt-8 flex flex-wrap items-start gap-3">
              {guestAction}

              {accountAction}
            </div>

            <p
              id="development-notice"
              className="mt-4 max-w-lg text-sm text-muted"
            >
              Guest access and account sign-in are being connected.
              Chat is still in development.
            </p>
          </div>

          <section
            aria-labelledby="preview-title"
            className="overflow-hidden rounded-panel border border-divider bg-surface"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-divider px-5 py-4">
              <h2 id="preview-title" className="font-medium">
                Planned chat interface
              </h2>
              <span className="text-sm text-muted">Illustrative example</span>
            </div>

            <div className="space-y-6 p-5 sm:p-6">
              <div className="flex justify-end">
                <p className="max-w-[90%] rounded-panel bg-surface-raised px-4 py-3">
                  Where should I start with maintenance?
                </p>
              </div>

              <div>
                <p className="mb-2 text-sm font-medium text-accent">askm6</p>
                <p className="max-w-prose leading-relaxed">
                  Start with your year and market. Engine and transmission
                  details help identify the information that applies.
                </p>
              </div>

              <div className="rounded-control border border-divider px-4 py-4">
                <p className="text-sm font-medium">Source reference preview</p>
                <p className="mt-1 text-sm text-muted">
                  Document, section and vehicle applicability will appear here.
                </p>
              </div>
            </div>

            <p className="border-t border-divider px-5 py-3 text-sm text-muted">
              Design preview — no AI response has been generated.
            </p>
          </section>
        </section>

        <section
          id="about"
          aria-labelledby="about-title"
          className="scroll-mt-6 border-t border-divider py-10"
        >
          <h2 id="about-title" className="sr-only">
            What askm6 is being built for
          </h2>

          <div className="grid gap-8 md:grid-cols-3">
            {capabilities.map((capability) => (
              <div key={capability.title}>
                <h3 className="text-lg font-medium">{capability.title}</h3>
                <p className="mt-2 max-w-sm leading-relaxed text-muted">
                  {capability.description}
                </p>
              </div>
            ))}
          </div>
        </section>
      </main>

      <footer className="mx-auto flex w-full max-w-7xl flex-col gap-4 border-t border-divider px-6 py-6 text-sm text-muted sm:flex-row sm:items-center sm:justify-between lg:px-10">
        <p>Independent, unofficial and unaffiliated with Mazda.</p>
        <PrivacyNoticeLink />
        {serviceStatus}
      </footer>

      {accountPanel}
    </div>
  )
}
