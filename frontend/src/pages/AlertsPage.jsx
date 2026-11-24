// Security Alerts - the triage queue.
//
// An alert is a single signal ("10 failed SSH logins from 192.168.56.20").
// Analysts review alerts, change their status, and escalate related alerts
// into an incident. Every alert shows WHAT produced it ("Detected by").
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Bell, Filter, Gauge, Plus, Briefcase, X } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'
import ErrorPanel from '../components/ErrorPanel.jsx'
import Pagination from '../components/Pagination.jsx'
import { ALERT_STATUSES, SEVERITIES, DemoBadge, SeverityBadge, StatusBadge } from '../components/Badges.jsx'
import { apiFetch, qs } from '../api/client.js'
import { useApi } from '../hooks/useApi.js'
import { useDebounce } from '../hooks/useDebounce.js'
import { useAuth } from '../auth/AuthContext.jsx'
import { formatDate, SOURCE_LABELS } from '../utils/format.js'

const LIMIT = 25

function NewAlertForm({ onCreated, onCancel }) {
  const [form, setForm] = useState({ title: '', severity: 'medium', src_ip: '', dst_ip: '', description: '' })
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const set = (field) => (e) => setForm({ ...form, [field]: e.target.value })

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const body = { ...form, src_ip: form.src_ip || null, dst_ip: form.dst_ip || null }
      onCreated(await apiFetch('/alerts', { method: 'POST', body }))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="Raise a manual alert" icon={Plus} className="mb-6"
      actions={<button type="button" onClick={onCancel} className="text-soc-muted hover:text-soc-text" aria-label="Close"><X className="h-4 w-4" /></button>}>
      <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4" noValidate>
        {error && <p role="alert" className="text-sm text-rose-300 sm:col-span-2 lg:col-span-4">{error}</p>}
        <div className="sm:col-span-2">
          <label htmlFor="na-title" className="label">Title</label>
          <input id="na-title" className="input" required minLength={3} maxLength={200} value={form.title} onChange={set('title')} />
        </div>
        <div>
          <label htmlFor="na-sev" className="label">Severity</label>
          <select id="na-sev" className="input" value={form.severity} onChange={set('severity')}>
            {SEVERITIES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
        </div>
        <div />
        <div>
          <label htmlFor="na-src" className="label">Source IP</label>
          <input id="na-src" className="input font-mono" placeholder="optional" value={form.src_ip} onChange={set('src_ip')} />
        </div>
        <div>
          <label htmlFor="na-dst" className="label">Destination IP</label>
          <input id="na-dst" className="input font-mono" placeholder="optional" value={form.dst_ip} onChange={set('dst_ip')} />
        </div>
        <div className="sm:col-span-2">
          <label htmlFor="na-desc" className="label">Description</label>
          <input id="na-desc" className="input" maxLength={5000} value={form.description} onChange={set('description')} />
        </div>
        <div className="sm:col-span-2 lg:col-span-4">
          <button type="submit" className="btn-primary" disabled={busy || form.title.length < 3}>
            {busy ? 'Saving…' : 'Create alert'}
          </button>
          <span className="ml-3 text-xs text-soc-muted">Recorded as "Detected by: Analyst" under your name.</span>
        </div>
      </form>
    </Card>
  )
}

export default function AlertsPage() {
  const { hasRole } = useAuth()
  const canEdit = hasRole('analyst')
  const navigate = useNavigate()

  const [filters, setFilters] = useState({ q: '', severity: '', status: '', source: '', include_simulated: true })
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState(new Set())
  const [showNew, setShowNew] = useState(false)
  const [actionError, setActionError] = useState(null)
  const q = useDebounce(filters.q)

  const { data, error, loading, reload } = useApi(
    `/alerts${qs({ ...filters, q, limit: LIMIT, offset })}`,
  )

  const setFilter = (field) => (e) => {
    const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value
    setFilters({ ...filters, [field]: value })
    setOffset(0)
  }

  function toggle(id) {
    const next = new Set(selected)
    next.has(id) ? next.delete(id) : next.add(id)
    setSelected(next)
  }

  async function createIncident() {
    const title = window.prompt('Incident title', 'Investigation of selected alerts')
    if (!title) return
    setActionError(null)
    try {
      const incident = await apiFetch('/incidents', { method: 'POST', body: { title, alert_ids: [...selected] } })
      navigate(`/incidents/${incident.id}`)
    } catch (err) {
      setActionError(err)
    }
  }

  const columns = [
    ...(canEdit ? [{
      key: 'select', label: '',
      render: (a) => (
        <input type="checkbox" aria-label={`Select alert ${a.id}`} disabled={a.incident_id !== null}
          checked={selected.has(a.id)} onChange={() => toggle(a.id)} />
      ),
    }] : []),
    { key: 'severity', label: 'Severity', render: (a) => <SeverityBadge severity={a.severity} /> },
    {
      key: 'title', label: 'Alert',
      render: (a) => (
        <Link to={`/alerts/${a.id}`} className="flex items-center gap-2 font-medium hover:text-soc-accent">
          {a.title} {a.is_simulated && <DemoBadge />}
        </Link>
      ),
    },
    { key: 'src_ip', label: 'Source IP', render: (a) => <code className="font-mono text-xs">{a.src_ip ?? '—'}</code> },
    { key: 'dst_ip', label: 'Destination IP', render: (a) => <code className="font-mono text-xs">{a.dst_ip ?? '—'}</code> },
    { key: 'source', label: 'Detected by', render: (a) => SOURCE_LABELS[a.source] + (a.detection_rule_id ? ` · ${a.detection_rule_id}` : '') },
    { key: 'status', label: 'Status', render: (a) => <StatusBadge status={a.status} /> },
    { key: 'incident', label: 'Incident', render: (a) => a.incident_id ? <Link className="text-soc-accent" to={`/incidents/${a.incident_id}`}>#{a.incident_id}</Link> : '—' },
    { key: 'detected_at', label: 'Detected at', render: (a) => formatDate(a.detected_at) },
  ]

  return (
    <>
      <PageHeader
        title="Security Alerts"
        description="Triage alerts by severity, review source and destination, and track investigation status."
        actions={canEdit && (
          <>
            <button type="button" className="btn-secondary" disabled={selected.size === 0} onClick={createIncident}>
              <Briefcase className="h-4 w-4" aria-hidden="true" /> Create incident ({selected.size})
            </button>
            <button type="button" className="btn-primary" onClick={() => setShowNew(true)}>
              <Plus className="h-4 w-4" aria-hidden="true" /> New alert
            </button>
          </>
        )}
      />

      {showNew && (
        <NewAlertForm onCancel={() => setShowNew(false)} onCreated={() => { setShowNew(false); reload() }} />
      )}
      {error && <ErrorPanel error={error} onRetry={reload} />}
      {actionError && <ErrorPanel error={actionError} />}

      <Card title="Filters" icon={Filter}>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <div className="sm:col-span-2">
            <label htmlFor="q" className="label">Search</label>
            <input id="q" className="input" placeholder="IP address, title, rule ID…" maxLength={100}
              value={filters.q} onChange={setFilter('q')} />
          </div>
          <div>
            <label htmlFor="sev" className="label">Severity</label>
            <select id="sev" className="input" value={filters.severity} onChange={setFilter('severity')}>
              <option value="">All severities</option>
              {SEVERITIES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="status" className="label">Status</label>
            <select id="status" className="input" value={filters.status} onChange={setFilter('status')}>
              <option value="">All statuses</option>
              {ALERT_STATUSES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="source" className="label">Detected by</label>
            <select id="source" className="input" value={filters.source} onChange={setFilter('source')}>
              <option value="">All sources</option>
              {Object.entries(SOURCE_LABELS).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
            </select>
          </div>
        </div>
        <label className="mt-4 inline-flex items-center gap-2 text-sm text-soc-muted">
          <input type="checkbox" checked={filters.include_simulated} onChange={setFilter('include_simulated')} />
          Include demo data
        </label>
      </Card>

      <Card title="Alert queue" icon={Bell} className="mt-6">
        <DataTable
          caption="Alert queue"
          columns={columns}
          rows={data?.items ?? []}
          empty={
            <EmptyState icon={Bell} title={loading ? 'Loading…' : 'No alerts match'}>
              Alerts are created by detection rules, Nmap findings, Wazuh, or manually by an analyst.
            </EmptyState>
          }
        />
        <Pagination total={data?.total} limit={LIMIT} offset={offset} onChange={setOffset} />
      </Card>

      <Card title="Severity classification" icon={Gauge} className="mt-6">
        <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {SEVERITIES.map((s) => (
            <div key={s.id} className="rounded-lg border border-soc-border bg-soc-bg p-3">
              <dt><SeverityBadge severity={s.id} /></dt>
              <dd className="mt-2 text-xs text-soc-muted">{s.description}</dd>
            </div>
          ))}
        </dl>
      </Card>
    </>
  )
}
