import App from './App'
import PrivacyNotice from './components/PrivacyNotice'

export default function Page() {
  const path = window.location.pathname
  return path === '/privacy' || path === '/privacy/' ? <PrivacyNotice /> : <App />
}
