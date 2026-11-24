// Sidebar navigation, built from config/navigation.js.
// <NavLink> knows whether its route is active, so we can highlight it and
// it sets aria-current="page" automatically for screen readers.
import { NavLink } from 'react-router-dom'
import { ShieldCheck, X } from 'lucide-react'
import { NAV_GROUPS } from '../config/navigation.js'

export default function Sidebar({ onClose }) {
  return (
    <nav className="flex h-full flex-col border-r border-soc-border bg-soc-panel" aria-label="Main">
      {/* Brand */}
      <div className="flex h-16 items-center justify-between border-b border-soc-border px-5">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-6 w-6 text-soc-accent" aria-hidden="true" />
          <span className="text-lg font-bold tracking-tight">
            Mini <span className="text-soc-accent">SOC</span>
          </span>
        </div>
        {/* Close button only exists in the mobile drawer */}
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-1 text-soc-muted hover:bg-soc-raised hover:text-soc-text"
            aria-label="Close navigation"
          >
            <X className="h-5 w-5" />
          </button>
        )}
      </div>

      {/* Menu groups */}
      <div className="flex-1 space-y-6 overflow-y-auto px-3 py-5">
        {NAV_GROUPS.map((group) => (
          <div key={group.label}>
            <p className="mb-2 px-3 text-[11px] font-semibold uppercase tracking-widest text-soc-muted">
              {group.label}
            </p>
            <ul className="space-y-1">
              {group.items.map(({ to, label, icon: Icon }) => (
                <li key={to}>
                  <NavLink
                    to={to}
                    end={to === '/'} /* "/" would otherwise match every route */
                    className={({ isActive }) =>
                      [
                        'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                        isActive
                          ? 'bg-soc-accent/10 text-soc-accent ring-1 ring-inset ring-soc-accent/30'
                          : 'text-soc-muted hover:bg-soc-raised hover:text-soc-text',
                      ].join(' ')
                    }
                  >
                    <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                    {label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <div className="border-t border-soc-border px-5 py-4 text-xs text-soc-muted">
        Lab use only. Scan systems you own or are authorized to test.
      </div>
    </nav>
  )
}
