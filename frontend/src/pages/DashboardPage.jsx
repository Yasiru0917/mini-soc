// SOC Dashboard - the analyst's overview.
//
// Phase 2: layout only. Every metric shows "-" (no data source), not 0,
// because there is no backend to count anything yet.
// Phase 3/4: values will come from GET /api/v1/dashboard/summary.
import { Activity, Briefcase, Radio, Fingerprint } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import PlaceholderNotice from '../components/PlaceholderNotice.jsx'
import StatCard from '../components/StatCard.jsx'
import Card from '../components/Card.jsx'
import EmptyState from '../components/EmptyState.jsx'
import { DemoBadge, STATUSES } from '../components/Badges.jsx'

// Each record will say which mechanism produced it. Shown here so the
// dashboard explains its own data rules.
const DATA_SOURCES = [
  { id: 'nmap', label: 'Nmap scan', phase: 5 },
  { id: 'log_rule', label: 'Log detection rule', phase: 6 },
  { id: 'pcap', label: 'Packet capture (TShark)', phase: 6 },
  { id: 'wazuh', label: 'Wazuh SIEM', phase: 7 },
  { id: 'threat_intel', label: 'Threat intelligence', phase: 8 },
  { id: 'manual', label: 'Analyst (manual entry)', phase: 4 },
]

export default function DashboardPage() {
  return (
    <>
      <PageHeader
        title="SOC Dashboard"
        description="Overview of alerts, incidents and network activity across the lab environment."
      />

      <PlaceholderNotice phase="3–4">
        The backend and database do not exist yet, so no metrics are shown. A dash (—) means
        "no data source", not "zero alerts".
      </PlaceholderNotice>

      {/* Alert counts by severity */}
      <section aria-label="Alert metrics" className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Total alerts" value={null} />
        <StatCard label="Critical" value={null} accentClass="bg-sev-critical" />
        <StatCard label="High" value={null} accentClass="bg-sev-high" />
        <StatCard label="Medium" value={null} accentClass="bg-sev-medium" />
        <StatCard label="Low" value={null} accentClass="bg-sev-low" />
        <StatCard label="Open incidents" value={null} accentClass="bg-soc-muted" />
      </section>

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card title="Recent security events" icon={Activity} className="lg:col-span-2">
          <EmptyState icon={Activity} title="No events to display">
            Events will appear here only when a real detection source (scan, log rule, Wazuh)
            or a clearly-marked demo record creates them.
          </EmptyState>
        </Card>

        <Card title="Incident statistics" icon={Briefcase}>
          <ul className="space-y-2 text-sm">
            {STATUSES.map((s) => (
              <li key={s.id} className="flex items-center justify-between">
                <span className="text-soc-muted">{s.label}</span>
                <span className="font-mono">—</span>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Network activity overview" icon={Radio} className="lg:col-span-2">
          <EmptyState icon={Radio} title="No network data yet">
            Device and service counts come from authorized Nmap scans (Phase 5). Traffic
            summaries come from uploaded packet captures (Phase 6).
          </EmptyState>
        </Card>

        <Card title="Data provenance" icon={Fingerprint}>
          <p className="mb-3 text-xs text-soc-muted">
            Every alert records the mechanism that produced it. Simulated records are always
            tagged <DemoBadge />.
          </p>
          <ul className="space-y-1.5 text-sm">
            {DATA_SOURCES.map((src) => (
              <li key={src.id} className="flex items-center justify-between gap-2">
                <span>{src.label}</span>
                <span className="text-xs text-soc-muted">Phase {src.phase}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </>
  )
}
