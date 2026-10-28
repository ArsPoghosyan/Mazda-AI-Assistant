import App from './App'
import PrivacyNotice from './components/PrivacyNotice'
import TermsOfService from './components/TermsOfService'
import NotFound from './components/NotFound'

export default function Page() {
  const path = window.location.pathname
  if (path === '/privacy' || path === '/privacy/') return <PrivacyNotice />
  if (path === '/terms' || path === '/terms/') return <TermsOfService />
  if (path === '/' || path === '/index.html') return <App />
  return <NotFound />
}
