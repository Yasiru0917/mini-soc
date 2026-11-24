// Security Alerts - triage queue for everything the detection sources raise.
//
// An alert is a single signal ("10 failed SSH logins from 192.168.56.20").
// Analysts triage alerts; serious ones are escalated into incidents.
import { Bell, Filter, Gauge } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import PlaceholderNotice from '../components/PlaceholderNotice.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'
import { SEVERITIES, STATUSES, SeverityBadge } from '../components/Badges.jsx'

const COLUMNS = [
  { key: 'severity', label: 'Severity' },
  { key: 'title', label: 'Alert' },
  { key: 'src_ip', label: 'Source IP' },
  { key: 'dst_ip', label: 'Destination IP' },
  { key: 'source', label: 'Detected by' },
  { key: 'status', label: 'Status' },
  { key: 'detected_at', label: 'Detected at (UTC)' },
]

export default function AlertsPage() {
  return (
    <>
      <PageHeader
        title="Security Alerts"
        description="Triage alerts by severity, review source and destination, and track investigation status."
      />

      <PlaceholderNotice phase={4}>
        Alert storage and triage are not built yet. The list is empty because no detection
        source exists. No sample alerts have been invented.
      </PlaceholderNotice>

      {/* Filters (disabled until there is data to filter) */}
      <Card title="Filters" icon={Filter}>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="sm:col-span-2">
            <label htmlFor="q" className="label">Search</label>
            <input id="q" className="input" placeholder="IP address, title, rule…" disabled />
          </div>
          <div>
            <label htmlFor="sev" className="label">Severity</label>
            <select id="sev" className="input" disabled>
              <option>All severities</option>
              {SEVERITIES.map((s) => <option key={s.id}>{s.label}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="status" className="label">Status</label>
            <select id="status" className="input" disabled>
              <option>All statuses</option>
              {STATUSES.map((s) => <option key={s.id}>{s.label}</option>)}
            </select>
          </div>
        </div>
      </Card>

      <Card title="Alert queue" icon={Bell} className="mt-6">
        <DataTable
          caption="Alert queue"
          columns={COLUMNS}
          empty={<EmptyState icon={Bell} title="No alerts">Alerts are created by detection rules, Nmap findings, Wazuh, or manually by an analyst.</EmptyState>}
        />
      </Card>

      {/* Severity legend: a shared definition of each level */}
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
