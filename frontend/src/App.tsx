import { useEffect, useState } from 'react'

type ApiStatus = 'checking' | 'connected' | 'unavailable'

const statusMessages: Record<ApiStatus, string> = {
  checking: 'Checking API connection…',
  connected: 'API connected',
  unavailable: 'API unavailable. Start the backend and try again.',
}

export default function App() {
  const [status, setStatus] = useState<ApiStatus>('checking')
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), 5000)
    let active = true

    async function checkHealth() {
      try {
        const response = await fetch('/api/v1/health', { signal: controller.signal })
        if (!response.ok) throw new Error('Health request failed')
        const body: unknown = await response.json()
        if (
          typeof body !== 'object' ||
          body === null ||
          !('status' in body) || body.status !== 'ok' ||
          !('service' in body) || body.service !== 'mazda6-assistant-api'
        ) throw new Error('Unexpected health response')
        if (active) setStatus('connected')
      } catch {
        if (active) setStatus('unavailable')
      } finally {
        window.clearTimeout(timeout)
      }
    }

    void checkHealth()
    return () => {
      active = false
      window.clearTimeout(timeout)
      controller.abort()
    }
  }, [attempt])

  return (
    <main className="mx-auto flex min-h-dvh max-w-3xl flex-col justify-center px-6 py-12">
      <p className="text-sm font-semibold tracking-widest text-teal-300">IN DEVELOPMENT</p>
      <h1 className="mt-4 text-4xl font-semibold tracking-tight sm:text-5xl">Mazda6 AI Assistant</h1>
      <p className="mt-5 max-w-xl text-lg leading-relaxed text-slate-300">
        A foundation for source-grounded Mazda6 information and maintenance guidance.
        Chat and vehicle features are coming in later milestones.
      </p>
      <section aria-label="Service status" className="mt-8 rounded-xl border border-slate-700 p-5">
        <p role="status" aria-live="polite">{statusMessages[status]}</p>
        {status === 'unavailable' && (
          <button
            className="mt-4 rounded-md bg-teal-300 px-4 py-2 font-semibold text-slate-950 hover:bg-teal-200 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-teal-300"
            onClick={() => { setStatus('checking'); setAttempt((value) => value + 1) }}
          >
            Try again
          </button>
        )}
      </section>
      <footer className="mt-10 text-sm text-slate-400">
        An independent project. Unofficial and unaffiliated with Mazda.
      </footer>
    </main>
  )
}
