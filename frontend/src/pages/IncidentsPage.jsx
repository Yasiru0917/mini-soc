// Incident Management - investigations built from one or more alerts.
//
// Alert vs incident: an alert is a signal; an incident is a confirmed (or
// suspected) security problem that someone owns, with notes, evidence and a
// documented resolution.
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Briefcase, Plus, X, GitBranch, ChevronRight } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'
import ErrorPanel from '../components/ErrorPanel.jsx'
import Pagination from '../components/Pagination.jsx'
import { SEVERITIES, STATUSES, DemoBadge, SeverityBadge, StatusBadge } from '../components/Badges.jsx'
import { apiFetch, qs } from '../api/client.js'
import { useApi } from '../hooks/useApi.js'
import { useDebounce } from '../hooks/useDebounce.js'
import { useAuth } from '../auth/AuthContext.jsx'
import { formatDate } from '../utils/format.js'

const LIMIT = 25
const LIFECYCLE = ['New', 'Investigating', 'Contained', 'Resolved', 'Closed']

function NewIncidentForm({ onCancel }) {
  const navigate = useNavigate()
  const [form, setForm] = useState({ title: '', severity: 'medium', description: '' })
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const set = (f) => (e) => setForm({ ...form, [f]: e.target.value })

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const incident = await apiFetch('/incidents', { method: 'POST', body: form })
      navigate(`/incidents/${incident.id}`)
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  return (
    <Card title="New incident" icon={Plus} className="mb-6"
      actions={<button type="button" onClick={onCancel} className="text-soc-muted hover:text-soc-text" aria-label="Close"><X className="h-4 w-4" /></button>}>
      <form onSubmit={submit} className="grid gap-4 sm:grid-cols-3" noValidate>
        {error && <p role="alert" className="text-sm text-rose-300 sm:col-span-3">{error}</p>}
        <div className="sm:col-span-2">
          <label htmlFor="ni-title" className="label">Title</label>
          <input id="ni-title" className="input" maxLength={200} value={form.title} onChange={set('title')} />
        </div>
        <div>
          <label htmlFor="ni-sev" className="label">Severity</label>
          <select id="ni-sev" className="input" value={form.severity} onChange={set('severity')}>
            {SEVERITIES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
        </div>
        <div className="sm:col-span-3">
          <label htmlFor="ni-desc" className="label">Description</label>
          <textarea id="ni-desc" rows={3} className="input" maxLength={10000} value={form.description} onChange={set('description')} />
        </div>
        <div className="sm:col-span-3">
          <button type="submit" className="btn-primary" disabled={busy || form.title.length < 3}>Create incident</button>
          <span className="ml-3 text-xs text-soc-muted">Tip: you can also select alerts on the Alerts page and create an incident from them.</span>
        </div>
      </form>
    </Card>
  )
}

export default function IncidentsPage() {
  const { hasRole } = useAuth()
  const [filters, setFilters] = useState({ q: '', status: '', severity: '', include_simulated: true })
  const [offset, setOffset] = useState(0)
  const [showNew, setShowNew] = useState(false)
  const q = useDebounce(filters.q)
  const { data, error, loading, reload } = useApi(`/incidents${qs({ ...filters, q, limit: LIMIT, offset })}`)

  const setFilter = (f) => (e) => {
    setFilters({ ...filters, [f]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })
    setOffset(0)
  }

  const columns = [
    { key: 'id', label: 'ID', render: (i) => <span className="font-mono">#{i.id}</span> },
    {
      key: 'title', label: 'Title',
      render: (i) => (
        <Link to={`/incidents/${i.id}`} className="flex items-center gap-2 font-medium hover:text-soc-accent">
          {i.title} {i.is_simulated && <DemoBadge />}
        </Link>
      ),
    },
    { key: 'severity', label: 'Severity', render: (i) => <SeverityBadge severity={i.severity} /> },
    { key: 'status', label: 'Status', render: (i) => <StatusBadge status={i.status} /> },
    { key: 'assignee', label: 'Assignee', render: (i) => i.assignee ?? 'Unassigned' },
    { key: 'alert_count', label: 'Linked alerts' },
    { key: 'updated_at', label: 'Last updated', render: (i) => formatDate(i.updated_at) },
  ]

  return (
    <>
      <PageHeader
        title="Incident Management"
        description="Escalate alerts into incidents, record investigation notes and evidence, and document the resolution."
        actions={hasRole('analyst') && (
          <button type="button" className="btn-primary" onClick={() => setShowNew(true)}>
            <Plus className="h-4 w-4" aria-hidden="true" /> New incident
          </button>
        )}
      />
      {showNew && <NewIncidentForm onCancel={() => setShowNew(false)} />}
      {error && <ErrorPanel error={error} onRetry={reload} />}

      <Card title="Incidents" icon={Briefcase}>
        <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <input className="input sm:col-span-2" placeholder="Search title or description…" aria-label="Search incidents"
            maxLength={100} value={filters.q} onChange={setFilter('q')} />
          <select className="input" aria-label="Status filter" value={filters.status} onChange={setFilter('status')}>
            <option value="">All statuses</option>
            {STATUSES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
          <select className="input" aria-label="Severity filter" value={filters.severity} onChange={setFilter('severity')}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
        </div>
        <label className="mb-2 inline-flex items-center gap-2 text-sm text-soc-muted">
          <input type="checkbox" checked={filters.include_simulated} onChange={setFilter('include_simulated')} />
          Include demo data
        </label>
        <DataTable caption="Incidents" columns={columns} rows={data?.items ?? []}
          empty={<EmptyState icon={Briefcase} title={loading ? 'Loading…' : 'No incidents'} />} />
        <Pagination total={data?.total} limit={LIMIT} offset={offset} onChange={setOffset} />
      </Card>

      <Card title="Investigation lifecycle" icon={GitBranch} className="mt-6">
        <ol className="flex flex-wrap items-center gap-2 text-sm">
          {LIFECYCLE.map((step, i) => (
            <li key={step} className="flex items-center gap-2">
              <span className="rounded-md border border-soc-border bg-soc-bg px-2.5 py-1">{step}</span>
              {i < LIFECYCLE.length - 1 && <ChevronRight className="h-4 w-4 text-soc-muted" aria-hidden="true" />}
            </li>
          ))}
        </ol>
        <p className="mt-3 text-xs text-soc-muted">
          Based on the NIST incident response cycle. Resolving, closing or marking an incident as a
          false positive requires a written resolution.
        </p>
      </Card>
    </>
  )
}
