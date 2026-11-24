// Login page.
//
// The password goes to POST /api/v1/auth/login once. The server checks it
// against the Argon2 hash and replies with an HttpOnly session cookie that
// JavaScript cannot read. We never store the password or token in the browser.
import { useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { ShieldCheck, LogIn, TriangleAlert } from 'lucide-react'
import { useAuth } from '../auth/AuthContext.jsx'

export default function LoginPage() {
  const { user, status, startupError, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  // Where to go after login: the page the user originally asked for.
  const from = location.state?.from && location.state.from !== '/login' ? location.state.from : '/'

  if (status === 'ready' && user) return <Navigate to={from} replace />

  async function handleSubmit(e) {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await login(username.trim(), password)
      navigate(from, { replace: true })
    } catch (err) {
      setError(err.message)
      setPassword('') // don't keep a wrong password in memory/the form
    } finally {
      setSubmitting(false)
    }
  }

  const shownError = error ?? startupError?.message

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center justify-center gap-2">
          <ShieldCheck className="h-8 w-8 text-soc-accent" aria-hidden="true" />
          <span className="text-2xl font-bold tracking-tight">
            Mini <span className="text-soc-accent">SOC</span>
          </span>
        </div>

        <form className="card space-y-4 p-6" onSubmit={handleSubmit} noValidate>
          <h1 className="text-lg font-semibold">Analyst sign in</h1>

          {shownError && (
            <div role="alert" className="flex gap-2 rounded-lg border border-sev-critical/40 bg-sev-critical/10 p-3 text-sm text-rose-200">
              <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              {shownError}
            </div>
          )}

          <div>
            <label htmlFor="username" className="label">Username</label>
            <input
              id="username"
              className="input"
              autoComplete="username"
              autoFocus
              required
              maxLength={64}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="password" className="label">Password</label>
            <input
              id="password"
              type="password"
              className="input"
              autoComplete="current-password"
              required
              maxLength={128}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <button type="submit" className="btn-primary w-full" disabled={submitting || !username || !password}>
            <LogIn className="h-4 w-4" aria-hidden="true" />
            {submitting ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <p className="mt-4 text-center text-xs text-soc-muted">
          No account? An admin creates accounts. The first admin is created with
          <code className="mx-1 font-mono">scripts/create_admin.py</code>.
        </p>
      </div>
    </main>
  )
}
