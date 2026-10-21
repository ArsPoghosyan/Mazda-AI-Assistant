import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { loadTurnstile, type TurnstileApi } from '../lib/turnstile'
import TurnstileChallenge from './TurnstileChallenge'

vi.mock('../lib/turnstile', () => ({
  loadTurnstile: vi.fn(),
}))

let api: TurnstileApi

beforeEach(() => {
  api = {
    ready: vi.fn<TurnstileApi['ready']>((callback) => callback()),
    render: vi.fn<TurnstileApi['render']>(() => 'test-widget'),
    reset: vi.fn<TurnstileApi['reset']>(),
    remove: vi.fn<TurnstileApi['remove']>(),
  }

  vi.mocked(loadTurnstile).mockReset()
  vi.mocked(loadTurnstile).mockResolvedValue(api)
})

afterEach(() => {
  cleanup()
})

async function mountChallenge() {
  const onToken = vi.fn<(token: string) => void>()
  const onInvalidated = vi.fn<() => void>()

  const view = render(
    <StrictMode>
      <TurnstileChallenge
        siteKey="public-test-site-key"
        onToken={onToken}
        onInvalidated={onInvalidated}
      />
    </StrictMode>,
  )

  await screen.findByText('Complete the check to continue.')

  const options = vi.mocked(api.render).mock.calls[0]?.[1]

  if (!options) {
    throw new Error('Expected a rendered verification widget')
  }

  return { view, onToken, onInvalidated, options }
}

test('delivers a token once under StrictMode', async () => {
  const { onToken, onInvalidated, options } = await mountChallenge()

  expect(api.render).toHaveBeenCalledTimes(1)
  expect(onToken).not.toHaveBeenCalled()

  act(() => {
    options.callback('synthetic-proof')
    options.callback('duplicate-proof')
  })

  expect(onToken).toHaveBeenCalledExactlyOnceWith('synthetic-proof')
  expect(onInvalidated).not.toHaveBeenCalled()
  expect(screen.getByText('Check completed.')).toBeDefined()
})

test.each([
  ['error', 'Verification could not be completed. Please try again.'],
  ['expired', 'Verification expired. Please try again.'],
  ['timeout', 'Verification took too long. Please try again.'],
] as const)(
  'invalidates a completed challenge after %s and ignores later tokens',
  async (event, message) => {
    const { onToken, onInvalidated, options } = await mountChallenge()

    act(() => {
      options.callback('synthetic-proof')
    })

    act(() => {
      if (event === 'error') {
        options['error-callback']('private-provider-detail')
      } else if (event === 'expired') {
        options['expired-callback']()
      } else {
        options['timeout-callback']?.()
      }

      options.callback('late-proof')
      options['expired-callback']()
    })

    expect(onToken).toHaveBeenCalledExactlyOnceWith('synthetic-proof')
    expect(onInvalidated).toHaveBeenCalledTimes(1)
    expect(screen.getByText(message)).toBeDefined()
    expect(screen.queryByText(/private-provider-detail/)).toBeNull()

    expect(
      screen.getByRole('button', { name: 'Retry verification' }),
    ).toBeDefined()
  },
)

test('retry removes the old widget and accepts a fresh proof', async () => {
  const { onToken, options } = await mountChallenge()

  act(() => {
    options['expired-callback']()
  })

  fireEvent.click(
    screen.getByRole('button', { name: 'Retry verification' }),
  )

  await screen.findByText('Complete the check to continue.')

  expect(api.remove).toHaveBeenCalledExactlyOnceWith('test-widget')
  expect(api.render).toHaveBeenCalledTimes(2)

  const freshOptions = vi.mocked(api.render).mock.calls[1]?.[1]

  if (!freshOptions) {
    throw new Error('Expected a replacement verification widget')
  }

  act(() => {
    options.callback('stale-proof')
    freshOptions.callback('fresh-proof')
  })

  expect(onToken).toHaveBeenCalledExactlyOnceWith('fresh-proof')
})

test('unmount removes the widget and ignores late callbacks', async () => {
  const { view, onToken, onInvalidated, options } = await mountChallenge()

  view.unmount()

  act(() => {
    options.callback('late-proof')
    options['error-callback']('late-error')
    options['expired-callback']()
    options['timeout-callback']?.()
  })

  expect(api.remove).toHaveBeenCalledExactlyOnceWith('test-widget')
  expect(onToken).not.toHaveBeenCalled()
  expect(onInvalidated).not.toHaveBeenCalled()
  expect(view.container.childElementCount).toBe(0)
})

test('does not render if the SDK finishes loading after unmount', async () => {
  let resolveSdk!: (value: TurnstileApi) => void

  const pendingSdk = new Promise<TurnstileApi>((resolve) => {
    resolveSdk = resolve
  })

  vi.mocked(loadTurnstile).mockReturnValue(pendingSdk)

  const onToken = vi.fn<(token: string) => void>()
  const onInvalidated = vi.fn<() => void>()

  const view = render(
    <StrictMode>
      <TurnstileChallenge
        siteKey="public-test-site-key"
        onToken={onToken}
        onInvalidated={onInvalidated}
      />
    </StrictMode>,
  )

  expect(screen.getByText('Loading verification…')).toBeDefined()

  view.unmount()

  await act(async () => {
    resolveSdk(api)
    await pendingSdk
  })

  expect(api.render).not.toHaveBeenCalled()
  expect(api.remove).not.toHaveBeenCalled()
  expect(onToken).not.toHaveBeenCalled()
  expect(onInvalidated).not.toHaveBeenCalled()
})