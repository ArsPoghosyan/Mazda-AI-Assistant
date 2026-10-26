export default function PrivacyNoticeLink({ newTab = false }: { newTab?: boolean }) {
  return (
    <a
      href="/privacy"
      target={newTab ? '_blank' : undefined}
      rel={newTab ? 'noopener noreferrer' : undefined}
      className="inline-flex min-h-11 items-center text-accent underline underline-offset-4 hover:text-accent-hover"
    >
      Privacy Notice{newTab && ' (opens in a new tab)'}
    </a>
  )
}
