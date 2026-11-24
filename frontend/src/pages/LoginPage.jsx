// Login page (UI only in Phase 2).
//
// Phase 3 plan (see docs/SECURITY.md):
//  - Password is sent once over the API; the server compares it with an
//    Argon2 hash (the password itself is never stored).
//  - The server returns the session token in an HttpOnly cookie, so
//    JavaScript - including any injected malicious script - cannot read it.
//  - Repeated failed logins are rate-limited.
import { Link } from 'react-router-dom'
import { ShieldCheck, LogIn, ArrowLeft } from 'lucide-react'
import PlaceholderNotice from '../components/PlaceholderNotice.jsx'

export default function LoginPage() {
  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center justify-center gap-2">
          <ShieldCheck className="h-8 w-8 text-soc-accent" aria-hidden="true" />
          <span className="text-2xl font-bold tracking-tight">
            Mini <span className="text-soc-accent">SOC</span>
          </span>
        </div>

        <PlaceholderNotice phase={3}>Authentication is not connected. Sign-in is disabled.</PlaceholderNotice>

        <form className="card space-y-4 p-6" onSubmit={(e) => e.preventDefault()}>
          <h1 className="text-lg font-semibold">Analyst sign in</h1>
          <div>
            <label htmlFor="username" className="label">Username</label>
            <input id="username" className="input" autoComplete="username" disabled />
          </div>
          <div>
            <label htmlFor="password" className="label">Password</label>
            <input id="password" type="password" className="input" autoComplete="current-password" disabled />
          </div>
          <button type="submit" className="btn-primary w-full" disabled>
            <LogIn className="h-4 w-4" aria-hidden="true" /> Sign in
          </button>
        </form>

        <Link to="/" className="mt-4 flex items-center justify-center gap-1 text-sm text-soc-muted hover:text-soc-text">
          <ArrowLeft className="h-4 w-4" aria-hidden="true" /> Back to dashboard
        </Link>
      </div>
    </main>
  )
}
