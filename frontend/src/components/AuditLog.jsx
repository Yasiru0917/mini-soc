// Admin view of the audit log: who did what, when, from where, and whether
// it was allowed. Refused actions (e.g. out-of-scope scans) appear as "denied".
import { useState } from 'react'
import DataTable from './DataTable.jsx'
import EmptyState from './EmptyState.jsx'
import ErrorPanel from './ErrorPanel.jsx'
import Pagination from './Pagination.jsx'
import { qs } from '../api/client.js'
import { useApi } from '../hooks/useApi.js'
import { formatDate } from '../utils/format.js'

const LIMIT = 25
const ACTIONS = ['auth', 'scan', 'scope', 'alert', 'incident', 'evidence', 'log', 'wazuh', 'threatintel', 'report', 'user']
const OUTCOME_STYLE = { success: 'text-emerald-400', failure: 'text-rose-300', denied: 'text-sev-high' }

export default function AuditLog() {
  const [filters, setFilters] = useState({ action: '', outcome: '' })
  const [offset, setOffset] = useState(0)
  const { data, error, loading, reload } = useApi(`/users/audit-log${qs({ ...filters, limit: LIMIT, offset })}`)
  const set = (f) => (e) => { setFilters({ ...filters, [f]: e.target.value }); setOffset(0) }

  const columns = [
    { key: 'timestamp', label: 'Time', render: (r) => formatDate(r.timestamp) },
    { key: 'username', label: 'User', render: (r) => r.username ?? '—' },
    { key: 'action', label: 'Action', render: (r) => <code className="font-mono text-xs">{r.action}</code> },
    { key: 'outcome', label: 'Outcome', render: (r) => <span className={OUTCOME_STYLE[r.outcome] ?? ''}>{r.outcome}</span> },
    { key: 'target', label: 'Target', render: (r) => <span className="block max-w-[14rem] truncate" title={r.target}>{r.target ?? '—'}</span> },
    { key: 'client_ip', label: 'From', render: (r) => <code className="font-mono text-xs">{r.client_ip ?? '—'}</code> },
    { key: 'detail', label: 'Detail', render: (r) => <span className="block max-w-xs truncate text-xs text-soc-muted" title={r.detail}>{r.detail ?? ''}</span> },
  ]

  return (
    <div>
      {error && <ErrorPanel error={error} onRetry={reload} />}
      <div className="mb-3 grid gap-3 sm:grid-cols-3">
        <select className="input" aria-label="Action" value={filters.action} onChange={set('action')}>
          <option value="">All actions</option>
          {ACTIONS.map((a) => <option key={a} value={a}>{a}.*</option>)}
        </select>
        <select className="input" aria-label="Outcome" value={filters.outcome} onChange={set('outcome')}>
          <option value="">All outcomes</option>
          <option value="success">success</option>
          <option value="failure">failure</option>
          <option value="denied">denied</option>
        </select>
      </div>
      <DataTable caption="Audit log" columns={columns} rows={data?.items ?? []}
        empty={<EmptyState title={loading ? 'Loading…' : 'No matching entries'} />} />
      <Pagination total={data?.total} limit={LIMIT} offset={offset} onChange={setOffset} />
    </div>
  )
}
