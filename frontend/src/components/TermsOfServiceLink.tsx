export default function TermsOfServiceLink({ newTab = false }: { newTab?: boolean }) {
  return (
    <a
      href="/terms"
      target={newTab ? '_blank' : undefined}
      rel={newTab ? 'noopener noreferrer' : undefined}
      className="inline-flex min-h-11 items-center text-accent underline underline-offset-4 hover:text-accent-hover"
    >
      Terms of Service
    </a>
  )
}
