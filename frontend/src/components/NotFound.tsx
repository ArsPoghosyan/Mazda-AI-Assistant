export default function NotFound() {
  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground">
      <title>Page not found | askm6</title>
      <header className="mx-auto w-full max-w-5xl px-6 py-6 sm:px-10">
        <a href="/" aria-label="askm6 home" className="inline-flex min-h-11 items-center text-xl font-semibold tracking-tight text-accent hover:text-accent-hover">askm6</a>
      </header>
      <main className="mx-auto flex w-full max-w-5xl flex-1 items-center px-6 py-12 sm:px-10 sm:py-20">
        <div className="max-w-xl border-l-2 border-accent pl-6 sm:pl-10">
          <p className="text-sm font-semibold tracking-[0.2em] text-accent">404</p>
          <h1 className="mt-4 text-4xl font-semibold tracking-tight sm:text-5xl">Page not found</h1>
          <p className="mt-5 max-w-md text-base leading-7 text-muted sm:text-lg">
            This page may have moved, or the address may be incorrect.
          </p>
          <a href="/" className="mt-8 inline-flex min-h-11 items-center justify-center rounded-control bg-accent px-6 py-3 font-semibold text-on-accent hover:bg-accent-hover">
            Back to home
          </a>
        </div>
      </main>
      <footer className="mx-auto w-full max-w-5xl border-t border-divider px-6 py-6 sm:px-10">
        <nav aria-label="Policy navigation" className="flex flex-wrap gap-x-6 gap-y-2 text-sm text-muted">
          <a href="/privacy" className="inline-flex min-h-11 items-center underline underline-offset-4 hover:text-foreground">Privacy Notice</a>
          <a href="/terms" className="inline-flex min-h-11 items-center underline underline-offset-4 hover:text-foreground">Terms of Service</a>
        </nav>
      </footer>
    </div>
  )
}
