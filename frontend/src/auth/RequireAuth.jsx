// Route guard: only renders its children for signed-in users.
// Otherwise it redirects to /login and remembers where you were going,
// so after login you land back on the same page.
//
// This is a usability feature. Security comes from the API returning 401
// for every protected endpoint, whatever the browser shows.
import { Navigate, useLocation } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import { useAuth } from './AuthContext.jsx'

export default function RequireAuth({ children }) {
  const { user, status } = useAuth()
  const location = useLocation()

  if (status === 'checking') {
    return (
      <div className="flex min-h-screen items-center justify-center gap-2 text-sm text-soc-muted" role="status">
        <ShieldCheck className="h-5 w-5 animate-pulse text-soc-accent" aria-hidden="true" />
        Checking session…
      </div>
    )
  }
  if (!user) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }
  return children
}
