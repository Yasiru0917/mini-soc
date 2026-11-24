// Live status of every integration, straight from GET /integrations/status.
import { RotateCw } from 'lucide-react'
import { useApi } from '../hooks/useApi.js'
import ErrorPanel from './ErrorPanel.jsx'

const STATE = {
  available: { dot: 'bg-emerald-400', label: 'Available' },
  not_configured: { dot: 'bg-soc-muted', label: 'Not configured' },
  not_installed: { dot: 'bg-sev-medium', label: 'Not installed' },
  unreachable: { dot: 'bg-sev-critical', label: 'Unreachable' },
  error: { dot: 'bg-sev-critical', label: 'Error' },
}

export default function IntegrationStatus() {
  const { data, error, loading, reload } = useApi('/integrations/status')
  if (error) return <ErrorPanel error={error} onRetry={reload} />

  return (
    <div>
      <ul className="divide-y divide-soc-border">
        {(data ?? []).map((i) => {
          const s = STATE[i.state] ?? STATE.error
          return (
            <li key={i.name} className="flex items-start justify-between gap-3 py-2.5">
              <div className="min-w-0">
                <p className="text-sm font-medium">{i.name}</p>
                <p className="break-words text-xs text-soc-muted">{i.version ?? i.detail}</p>
              </div>
              <span className="inline-flex shrink-0 items-center gap-1.5 text-xs">
                <span className={`h-2 w-2 rounded-full ${s.dot}`} aria-hidden="true" /> {s.label}
              </span>
            </li>
          )
        })}
      </ul>
      <button type="button" className="btn-secondary mt-3 px-3 py-1.5 text-xs" onClick={reload} disabled={loading}>
        <RotateCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" /> Re-check
      </button>
    </div>
  )
}
