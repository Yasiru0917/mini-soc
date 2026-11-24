// Top bar: menu button (mobile), page title (mobile), API health, user menu.
//
// The API chip shows the REAL result of GET /api/v1/health, re-checked
// every 30 seconds: green = API and database OK, red = unreachable/degraded.
import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Menu, Server, LogOut, UserRound } from 'lucide-react'
import { findNavItem } from '../config/navigation.js'
import { apiFetch } from '../api/client.js'
import { useAuth } from '../auth/AuthContext.jsx'

const HEALTH_INTERVAL_MS = 30_000

function useApiHealth() {
  const [health, setHealth] = useState({ state: 'checking' })

  useEffect(() => {
    let cancelled = false
    async function check() {
      try {
        const data = await apiFetch('/health')
        if (!cancelled) setHealth({ state: data.status === 'ok' ? 'ok' : 'degraded', data })
      } catch {
        if (!cancelled) setHealth({ state: 'down' })
      }
    }
    check()
    const timer = setInterval(check, HEALTH_INTERVAL_MS)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [])
  return health
}

const HEALTH_STYLE = {
  checking: { dot: 'bg-soc-muted', label: 'Checking…' },
  ok: { dot: 'bg-emerald-400', label: 'Online' },
  degraded: { dot: 'bg-sev-medium', label: 'Degraded' },
  down: { dot: 'bg-sev-critical', label: 'Unreachable' },
}

export default function Topbar({ onMenuClick }) {
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const { user, logout } = useAuth()
  const health = useApiHealth()
  const title = findNavItem(pathname)?.label ?? 'Page not found'
  const style = HEALTH_STYLE[health.state]

  async function handleLogout() {
    await logout().catch(() => {}) // local state is cleared either way
    navigate('/login', { replace: true })
  }

  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-soc-border bg-soc-bg/85 px-4 backdrop-blur sm:px-6 lg:px-8">
      <button
        type="button"
        onClick={onMenuClick}
        className="rounded-md p-2 text-soc-muted hover:bg-soc-raised hover:text-soc-text lg:hidden"
        aria-label="Open navigation"
      >
        <Menu className="h-5 w-5" />
      </button>

      {/* On mobile the sidebar is hidden, so show where we are here.
          (The page's real <h1> is in its PageHeader.) */}
      <p className="truncate text-base font-semibold lg:hidden">{title}</p>

      <div className="ml-auto flex items-center gap-2">
        <span
          className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-soc-border px-2.5 py-1 text-xs text-soc-muted"
          title={health.data ? `API v${health.data.version} · database ${health.data.database}` : 'API status'}
          role="status"
        >
          <Server className="h-3.5 w-3.5" aria-hidden="true" />
          <span className={`h-2 w-2 rounded-full ${style.dot}`} aria-hidden="true" />
          <span className="sr-only sm:not-sr-only">API: {style.label}</span>
        </span>

        {user && (
          <div className="flex items-center gap-2">
            <span className="hidden items-center gap-1.5 text-xs md:inline-flex">
              <UserRound className="h-4 w-4 text-soc-muted" aria-hidden="true" />
              <span className="font-medium">{user.username}</span>
              <span className="rounded-md border border-soc-border px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-soc-muted">
                {user.role}
              </span>
            </span>
            <button type="button" onClick={handleLogout} className="btn-secondary px-3 py-1.5 text-xs" aria-label="Sign out">
              <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="hidden sm:inline">Sign out</span>
            </button>
          </div>
        )}
      </div>
    </header>
  )
}
