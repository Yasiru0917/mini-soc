// Top bar: menu button (mobile), current page title, and status chips.
//
// The "API" chip is deliberately honest: there is no backend yet, so it
// says "Not connected" instead of pretending everything is online.
// Phase 3 replaces it with a real health check against the FastAPI server.
import { Link, useLocation } from 'react-router-dom'
import { Menu, Server, LogIn } from 'lucide-react'
import { findNavItem } from '../config/navigation.js'
import { CURRENT_PHASE } from '../config/appConfig.js'

export default function Topbar({ onMenuClick }) {
  const { pathname } = useLocation()
  const title = findNavItem(pathname)?.label ?? 'Page not found'

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
        <span className="hidden rounded-full border border-soc-border px-2.5 py-1 text-xs text-soc-muted md:inline">
          Dev build · Phase {CURRENT_PHASE}
        </span>
        <span
          className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-soc-border px-2.5 py-1 text-xs text-soc-muted"
          title="API not connected - the FastAPI backend is built in Phase 3"
        >
          <Server className="h-3.5 w-3.5" aria-hidden="true" />
          <span className="h-2 w-2 rounded-full bg-soc-muted" aria-hidden="true" />
          {/* On phones only the icon + grey dot show; screen readers still get the text */}
          <span className="sr-only sm:not-sr-only">API: Not connected</span>
        </span>
        <Link to="/login" className="btn-secondary px-3 py-1.5 text-xs" aria-label="Sign in">
          <LogIn className="h-3.5 w-3.5" aria-hidden="true" />
          <span className="hidden sm:inline">Sign in</span>
        </Link>
      </div>
    </header>
  )
}
