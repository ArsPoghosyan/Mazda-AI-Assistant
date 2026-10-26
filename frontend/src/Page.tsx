import App from './App'
import PrivacyNotice from './components/PrivacyNotice'
import TermsOfService from './components/TermsOfService'

export default function Page() {
  const path = window.location.pathname
  if (path === '/privacy' || path === '/privacy/') return <PrivacyNotice />
  if (path === '/terms' || path === '/terms/') return <TermsOfService />
  return <App />
}
