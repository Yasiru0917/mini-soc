// SOC Dashboard - the analyst's overview.
//
// Phase 3: alert and incident numbers are LIVE counts from the database via
// GET /api/v1/dashboard/summary. They are real zeros until detection
// sources exist (Phase 4+). Network activity is still a placeholder (Phase 5).
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, Briefcase, Radio, Fingerprint, RotateCw } from 'lucide-react'
import { SOURCE_LABELS } from '../utils/format.js'
import PageHeader from '../components/PageHeader.jsx'
import InfoNotice from '../components/InfoNotice.jsx'
import ErrorPanel from '../components/ErrorPanel.jsx'
import StatCard from '../components/StatCard.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'
import { DemoBadge, SeverityBadge, StatusBadge, STATUSES } from '../components/Badges.jsx'
import { useApi } from '../hooks/useApi.js'

// Each record says which mechanism produced it.
const DATA_SOURCES = [
  { id: 'nmap', label: 'Nmap scan', how: 'Risky exposed services, new devices' },
  { id: 'log_rule', label: 'Log detection rule', how: 'Rules R-001 to R-005 on uploaded logs' },
  { id: 'pcap', label: 'Packet capture', how: 'Rule R-006 on uploaded pcaps' },
  { id: 'wazuh', label: 'Wazuh SIEM', how: 'Imported Wazuh alerts' },
  { id: 'manual', label: 'Analyst', how: 'Raised manually, under their name' },
]

const RECENT_COLUMNS = [
  { key: 'severity', label: 'Severity', render: (a) => <SeverityBadge severity={a.severity} /> },
  {
    key: 'title',
    label: 'Alert',
    render: (a) => (
      <span className="flex items-center gap-2">
        {a.title} {a.is_simulated && <DemoBadge />}
      </span>
    ),
  },
  { key: 'src', label: 'Source → Destination', render: (a) => <code className="font-mono text-xs">{a.src_ip ?? '—'} → {a.dst_ip ?? '—'}</code> },
  { key: 'source', label: 'Detected by' },
  { key: 'status', label: 'Status', render: (a) => <StatusBadge status={a.status} /> },
  { key: 'detected_at', label: 'Time', render: (a) => new Date(a.detected_at).toLocaleString() },
]

export default function DashboardPage() {
  const [includeDemo, setIncludeDemo] = useState(true)
  const { data, error, loading, reload } = useApi(`/dashboard/summary?include_simulated=${includeDemo}`)

  // While loading (or on error) show "-" rather than a misleading number.
  const sev = data?.alerts.by_severity
  const hint = loading ? 'Loading…' : data ? 'Stored in database' : undefined

  return (
    <>
      <PageHeader
        title="SOC Dashboard"
        description="Overview of alerts, incidents and network activity across the lab environment."
        actions={
          <>
            <label className="btn-secondary cursor-pointer select-none">
              <input
                type="checkbox"
                className="accent-[var(--color-demo)]"
                checked={includeDemo}
                onChange={(e) => setIncludeDemo(e.target.checked)}
              />
              Include demo data
            </label>
            <button type="button" className="btn-secondary" onClick={reload} disabled={loading} aria-label="Refresh">
              <RotateCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
            </button>
          </>
        }
      />

      {error ? (
        <ErrorPanel error={error} onRetry={reload} />
      ) : (
        <InfoNotice title="Live data">
          Every number comes straight from the database. Alerts only exist when a detection source
          (Nmap scan, log rule, packet capture, Wazuh) or an analyst created them. Demo records are
          counted only while "Include demo data" is on.
        </InfoNotice>
      )}

      <section aria-label="Alert metrics" className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Total alerts" value={data?.alerts.total} hint={data?.alerts.simulated ? `${data.alerts.simulated} demo` : hint} />
        <StatCard label="Critical" value={sev?.critical} hint={hint} accentClass="bg-sev-critical" />
        <StatCard label="High" value={sev?.high} hint={hint} accentClass="bg-sev-high" />
        <StatCard label="Medium" value={sev?.medium} hint={hint} accentClass="bg-sev-medium" />
        <StatCard label="Low" value={sev?.low} hint={hint} accentClass="bg-sev-low" />
        <StatCard label="Open incidents" value={data?.incidents.open} hint={hint} accentClass="bg-soc-muted" />
      </section>

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card title="Recent security events" icon={Activity} className="lg:col-span-2">
          <DataTable
            caption="Recent alerts"
            columns={RECENT_COLUMNS}
            rows={data?.recent_alerts ?? []}
            empty={
              <EmptyState icon={Activity} title={loading ? 'Loading…' : 'No alerts recorded'}>
                Alerts appear here only when a real detection source or an analyst creates them.
                Demo records are always marked <DemoBadge />.
              </EmptyState>
            }
          />
        </Card>

        <Card title="Incident statistics" icon={Briefcase}>
          <ul className="space-y-2 text-sm">
            {STATUSES.map((s) => (
              <li key={s.id} className="flex items-center justify-between">
                <span className="text-soc-muted">{s.label}</span>
                <span className="font-mono">{data?.incidents.by_status[s.id] ?? '—'}</span>
              </li>
            ))}
            <li className="flex items-center justify-between border-t border-soc-border pt-2 font-medium">
              <span>Total</span>
              <span className="font-mono">{data?.incidents.total ?? '—'}</span>
            </li>
          </ul>
        </Card>

        <Card title="Network activity overview" icon={Radio} className="lg:col-span-2"
          actions={<Link to="/network" className="text-xs text-soc-accent">Network scanning →</Link>}>
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[
              ['Known devices', data?.network.devices],
              ['Seen in last 24h', data?.network.devices_up_24h],
              ['Open ports', data?.network.open_ports],
              ['Completed scans', data?.network.scans_completed],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg border border-soc-border bg-soc-bg p-3">
                <dt className="text-xs text-soc-muted">{label}</dt>
                <dd className="mt-1 font-mono text-2xl">{value ?? '—'}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-3 text-xs text-soc-muted">
            {data?.network.last_scan_at
              ? `Last completed scan: ${new Date(data.network.last_scan_at).toLocaleString()}. Counts come from authorized Nmap scans only.`
              : 'No completed scans yet. Run an authorized scan to build the inventory.'}
          </p>
          {data && Object.keys(data.alerts_by_source).length > 0 && (
            <div className="mt-4">
              <p className="mb-2 text-xs uppercase tracking-wider text-soc-muted">Alerts by detection source</p>
              <ul className="space-y-1.5">
                {Object.entries(data.alerts_by_source).sort((a, b) => b[1] - a[1]).map(([src, n]) => (
                  <li key={src} className="flex items-center gap-3 text-sm">
                    <span className="w-28 shrink-0 text-soc-muted">{SOURCE_LABELS[src] ?? src}</span>
                    <span className="h-2 rounded-full bg-soc-accent/70" style={{ width: `${(n / data.alerts.total) * 100}%`, minWidth: '4px' }} aria-hidden="true" />
                    <span className="font-mono text-xs">{n}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Card>

        <Card title="Data provenance" icon={Fingerprint}>
          <p className="mb-3 text-xs text-soc-muted">
            Every alert records the mechanism that produced it. Simulated records are always
            tagged <DemoBadge />.
          </p>
          <ul className="space-y-1.5 text-sm">
            {DATA_SOURCES.map((src) => (
              <li key={src.id} className="flex items-baseline justify-between gap-3">
                <span className="shrink-0">{src.label}</span>
                <span className="text-right text-xs text-soc-muted">{src.how}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </>
  )
}
