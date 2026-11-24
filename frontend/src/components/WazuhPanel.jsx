// Wazuh SIEM: connection test, agents, and manual alert sync.
import { useState } from 'react'
import { PlugZap, RefreshCw, ShieldAlert } from 'lucide-react'
import { apiFetch } from '../api/client.js'
import { useApi } from '../hooks/useApi.js'
import { useAuth } from '../auth/AuthContext.jsx'
import { formatDate } from '../utils/format.js'

export default function WazuhPanel() {
  const { hasRole } = useAuth()
  const { data: st, loading, reload } = useApi('/wazuh/status')
  const [sync, setSync] = useState(null)
  const [busy, setBusy] = useState(false)

  async function runSync() {
    setBusy(true)
    setSync(null)
    try {
      setSync({ ok: true, data: await apiFetch('/wazuh/sync', { method: 'POST' }) })
      reload()
    } catch (err) {
      setSync({ ok: false, message: err.message })
    } finally {
      setBusy(false)
    }
  }

  if (loading && !st) return <p className="text-sm text-soc-muted">Checking Wazuh connection…</p>

  return (
    <div className="space-y-3 text-sm">
      <div className="flex items-center gap-2">
        <span className={`h-2.5 w-2.5 rounded-full ${st?.reachable ? 'bg-emerald-400' : st?.configured ? 'bg-sev-critical' : 'bg-soc-muted'}`} aria-hidden="true" />
        <span className="font-medium">
          {st?.reachable ? `Connected · Wazuh ${st.manager_version}` : st?.configured ? 'Unreachable' : 'Not configured'}
        </span>
      </div>
      {st?.error && <p className="text-xs text-soc-muted">{st.error}</p>}
      {st?.reachable && (
        <dl className="grid grid-cols-2 gap-2 text-xs">
          <div><dt className="text-soc-muted">Agents</dt><dd>{st.agents_total}</dd></div>
          <div><dt className="text-soc-muted">Min. rule level imported</dt><dd>{st.min_rule_level}</dd></div>
          <div><dt className="text-soc-muted">Indexer</dt><dd>{st.indexer_configured ? 'Configured' : 'Not configured'}</dd></div>
          <div><dt className="text-soc-muted">Imported up to</dt><dd>{st.last_sync_cursor ? formatDate(st.last_sync_cursor) : 'Never synced'}</dd></div>
        </dl>
      )}
      {st?.configured && st.tls_verification === 'OFF' && (
        <p className="flex gap-2 rounded-lg border border-sev-medium/40 bg-sev-medium/10 p-2 text-xs text-amber-200">
          <ShieldAlert className="h-4 w-4 shrink-0" aria-hidden="true" />
          TLS certificate checking is OFF. Acceptable only on an isolated lab network; set WAZUH_CA_CERT instead.
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        <button type="button" className="btn-secondary px-3 py-1.5 text-xs" onClick={reload} disabled={loading}>
          <PlugZap className="h-3.5 w-3.5" aria-hidden="true" /> Test connection
        </button>
        {hasRole('analyst') && (
          <button type="button" className="btn-primary px-3 py-1.5 text-xs" onClick={runSync} disabled={busy || !st?.configured}>
            <RefreshCw className={`h-3.5 w-3.5 ${busy ? 'animate-spin' : ''}`} aria-hidden="true" /> Sync alerts now
          </button>
        )}
      </div>
      {sync && (
        <p role="status" className={`text-xs ${sync.ok ? 'text-emerald-400' : 'text-rose-300'}`}>
          {sync.ok
            ? `Fetched ${sync.data.fetched} Wazuh alert(s): ${sync.data.created} new, ${sync.data.duplicates} already imported.`
            : sync.message}
        </p>
      )}
    </div>
  )
}
