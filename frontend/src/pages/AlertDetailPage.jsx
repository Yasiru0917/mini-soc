// One alert: full details, provenance (what produced it), and triage actions.
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Fingerprint, ListChecks, Info } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import ErrorPanel from '../components/ErrorPanel.jsx'
import { ALERT_STATUSES, SEVERITIES, DemoBadge, SeverityBadge, StatusBadge } from '../components/Badges.jsx'
import { apiFetch } from '../api/client.js'
import { useApi } from '../hooks/useApi.js'
import { useAuth } from '../auth/AuthContext.jsx'
import { ALERT_TRANSITIONS } from '../config/workflow.js'
import { formatDate, SOURCE_LABELS } from '../utils/format.js'

function Field({ label, children }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wider text-soc-muted">{label}</dt>
      <dd className="mt-0.5 break-words text-sm">{children ?? '—'}</dd>
    </div>
  )
}

export default function AlertDetailPage() {
  const { id } = useParams()
  const { hasRole } = useAuth()
  const { data: alert, error, loading, reload } = useApi(`/alerts/${id}`)
  const [actionError, setActionError] = useState(null)

  async function update(body) {
    setActionError(null)
    try {
      await apiFetch(`/alerts/${id}`, { method: 'PATCH', body })
      reload()
    } catch (err) {
      setActionError(err)
    }
  }

  if (error) return <ErrorPanel error={error} onRetry={reload} />
  if (loading || !alert) return <p className="text-sm text-soc-muted">Loading…</p>

  const label = (statusId) => ALERT_STATUSES.find((s) => s.id === statusId)?.label ?? statusId

  return (
    <>
      <Link to="/alerts" className="mb-4 inline-flex items-center gap-1 text-sm text-soc-muted hover:text-soc-text">
        <ArrowLeft className="h-4 w-4" aria-hidden="true" /> All alerts
      </Link>
      <PageHeader title={`Alert #${alert.id}: ${alert.title}`} />
      <div className="mb-6 flex flex-wrap items-center gap-2">
        <SeverityBadge severity={alert.severity} />
        <StatusBadge status={alert.status} />
        {alert.is_simulated && <DemoBadge />}
      </div>
      {actionError && <ErrorPanel error={actionError} />}

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Details" icon={Info} className="lg:col-span-2">
          <dl className="grid gap-4 sm:grid-cols-2">
            <Field label="Source IP">
              <code className="font-mono">{alert.src_ip}</code>
              {alert.src_ip && hasRole('analyst') && (
                <Link className="ml-2 text-xs text-soc-accent" to={`/threat-intel?q=${encodeURIComponent(alert.src_ip)}`}>Check reputation →</Link>
              )}
            </Field>
            <Field label="Destination IP"><code className="font-mono">{alert.dst_ip}</code></Field>
            <Field label="Detected at">{formatDate(alert.detected_at)}</Field>
            <Field label="Last updated">{formatDate(alert.updated_at)}</Field>
            <Field label="Incident">
              {alert.incident_id ? <Link className="text-soc-accent" to={`/incidents/${alert.incident_id}`}>Incident #{alert.incident_id}</Link> : 'Not linked'}
            </Field>
            <div className="sm:col-span-2">
              <Field label="Description"><span className="whitespace-pre-wrap">{alert.description}</span></Field>
            </div>
          </dl>
        </Card>

        <Card title="Provenance" icon={Fingerprint}>
          <dl className="space-y-3">
            <Field label="Detected by">{SOURCE_LABELS[alert.source]}</Field>
            <Field label="Detection rule"><code className="font-mono">{alert.detection_rule_id}</code></Field>
            <Field label="Evidence reference"><code className="font-mono text-xs">{alert.raw_reference}</code></Field>
            <Field label="Simulated">{alert.is_simulated ? 'Yes - demo data, not a real detection' : 'No'}</Field>
          </dl>
        </Card>
      </div>

      {hasRole('analyst') && (
        <Card title="Triage" icon={ListChecks} className="mt-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
            <div>
              <p className="label">Change status</p>
              <div className="flex flex-wrap gap-2">
                {ALERT_TRANSITIONS[alert.status].map((next) => (
                  <button key={next} type="button" className="btn-secondary" onClick={() => update({ status: next })}>
                    {label(next)}
                  </button>
                ))}
              </div>
            </div>
            <div className="sm:ml-auto">
              <label htmlFor="sev" className="label">Severity</label>
              <select id="sev" className="input w-40" value={alert.severity} onChange={(e) => update({ severity: e.target.value })}>
                {SEVERITIES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
              </select>
            </div>
          </div>
        </Card>
      )}
    </>
  )
}
