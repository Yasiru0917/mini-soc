// Reports - export incident investigations (PDF/CSV) and alert lists (CSV).
//
// Downloads are ordinary links: the browser sends the session cookie itself.
// Every generated report is recorded with its SHA-256 so a recipient can
// verify the file they received is exactly what was generated.
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { FileText, Download, History, Sheet } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'
import ErrorPanel from '../components/ErrorPanel.jsx'
import { ALERT_STATUSES, SEVERITIES, DemoBadge, SeverityBadge, StatusBadge } from '../components/Badges.jsx'
import { apiUrl, qs } from '../api/client.js'
import { useApi } from '../hooks/useApi.js'
import { formatBytes, formatDate, SOURCE_LABELS } from '../utils/format.js'

const KIND_LABEL = { incident_pdf: 'Incident PDF', incident_csv: 'Incident CSV', alerts_csv: 'Alerts CSV' }
const SECTIONS = ['Executive summary', 'Timeline of events', 'Affected hosts and indicators',
  'Evidence list with SHA-256 hashes', 'Root cause and resolution', 'Recommendations']

export default function ReportsPage() {
  const incidents = useApi('/incidents?limit=50')
  const history = useApi('/reports?limit=30')
  const [filters, setFilters] = useState({ severity: '', status: '', source: '', include_simulated: true })

  const incidentColumns = [
    { key: 'id', label: 'Incident', render: (i) => <Link className="hover:text-soc-accent" to={`/incidents/${i.id}`}>#{i.id} {i.title} {i.is_simulated && <DemoBadge />}</Link> },
    { key: 'severity', label: 'Severity', render: (i) => <SeverityBadge severity={i.severity} /> },
    { key: 'status', label: 'Status', render: (i) => <StatusBadge status={i.status} /> },
    { key: 'updated_at', label: 'Updated', render: (i) => formatDate(i.updated_at) },
    {
      key: 'export', label: 'Export',
      render: (i) => (
        <div className="flex gap-2">
          <a className="btn-secondary px-2 py-1 text-xs" href={apiUrl(`/reports/incidents/${i.id}.pdf`)} onClick={() => setTimeout(history.reload, 1500)}>
            <Download className="h-3.5 w-3.5" aria-hidden="true" /> PDF
          </a>
          <a className="btn-secondary px-2 py-1 text-xs" href={apiUrl(`/reports/incidents/${i.id}.csv`)} onClick={() => setTimeout(history.reload, 1500)}>
            <Download className="h-3.5 w-3.5" aria-hidden="true" /> CSV
          </a>
        </div>
      ),
    },
  ]

  const historyColumns = [
    { key: 'kind', label: 'Type', render: (r) => KIND_LABEL[r.kind] ?? r.kind },
    { key: 'filename', label: 'File', render: (r) => <span className="font-mono text-xs">{r.filename}</span> },
    { key: 'size', label: 'Size', render: (r) => formatBytes(r.size_bytes) },
    { key: 'sha256', label: 'SHA-256', render: (r) => <code className="font-mono text-[11px] text-soc-muted" title={r.sha256}>{r.sha256.slice(0, 16)}…</code> },
    { key: 'by', label: 'By', render: (r) => r.generated_by },
    { key: 'at', label: 'Generated', render: (r) => formatDate(r.generated_at) },
  ]

  const set = (f) => (e) => setFilters({ ...filters, [f]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })

  return (
    <>
      <PageHeader title="Reports" description="Generate incident reports with findings and recommendations, exported as PDF or CSV." />
      {incidents.error && <ErrorPanel error={incidents.error} onRetry={incidents.reload} />}

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Incident reports" icon={FileText} className="lg:col-span-2">
          <DataTable caption="Incidents" columns={incidentColumns} rows={incidents.data?.items ?? []}
            empty={<EmptyState icon={FileText} title={incidents.loading ? 'Loading…' : 'No incidents to report on'}>Reports are generated only from real incident records.</EmptyState>} />
        </Card>
        <Card title="PDF report contents" icon={FileText}>
          <ol className="list-decimal space-y-1.5 pl-5 text-sm">
            {SECTIONS.map((s) => <li key={s}>{s}</li>)}
          </ol>
          <p className="mt-3 text-xs text-soc-muted">Incidents built from demo data carry a "SIMULATED DATA" banner in the PDF.</p>
        </Card>
      </div>

      <Card title="Alert export (CSV)" icon={Sheet} className="mt-6">
        <div className="grid gap-3 sm:grid-cols-3">
          <select className="input" aria-label="Severity" value={filters.severity} onChange={set('severity')}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
          <select className="input" aria-label="Status" value={filters.status} onChange={set('status')}>
            <option value="">All statuses</option>
            {ALERT_STATUSES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
          <select className="input" aria-label="Source" value={filters.source} onChange={set('source')}>
            <option value="">All sources</option>
            {Object.entries(SOURCE_LABELS).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
          </select>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-4">
          <label className="inline-flex items-center gap-2 text-sm text-soc-muted">
            <input type="checkbox" checked={filters.include_simulated} onChange={set('include_simulated')} /> Include demo data
          </label>
          <a className="btn-primary" href={apiUrl(`/reports/alerts.csv${qs(filters)}`)} onClick={() => setTimeout(history.reload, 1500)}>
            <Download className="h-4 w-4" aria-hidden="true" /> Download CSV
          </a>
        </div>
        <p className="mt-3 text-xs text-soc-muted">
          Cells starting with = + - @ are prefixed with a quote so spreadsheet programs can't execute them as formulas (CSV injection protection).
        </p>
      </Card>

      <Card title="Generated reports" icon={History} className="mt-6">
        <DataTable caption="Generated reports" columns={historyColumns} rows={history.data ?? []}
          empty={<EmptyState icon={History} title={history.loading ? 'Loading…' : 'No reports generated yet'} />} />
      </Card>
    </>
  )
}
