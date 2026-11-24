// Log Analysis - upload log files / packet captures and run detection rules.
//
// How it will work (Phase 6):
//  1. Upload a file. The server checks size, extension AND content
//     (e.g. a .pcap must start with the pcap "magic bytes").
//  2. The file is stored under a random name outside the web root and
//     its SHA-256 hash is recorded.
//  3. A parser turns each line into a structured event.
//  4. Detection rules look for suspicious patterns and raise alerts that
//     name the exact rule that fired.
import { Upload, FileSearch, ListChecks, Files } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import PlaceholderNotice from '../components/PlaceholderNotice.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'
import { PlannedBadge } from '../components/Badges.jsx'

// Planned limits (enforced by the backend, documented in docs/SECURITY.md).
const FORMATS = [
  { type: 'Linux auth log', ext: '.log, .txt', limit: '10 MB', example: '/var/log/auth.log' },
  { type: 'Web server access log', ext: '.log, .txt', limit: '10 MB', example: 'Apache / Nginx combined format' },
  { type: 'JSON lines', ext: '.json, .jsonl', limit: '10 MB', example: 'One JSON event per line' },
  { type: 'Packet capture', ext: '.pcap, .pcapng', limit: '50 MB', example: 'Saved from Wireshark' },
]

// Planned detection rules. These are rule DEFINITIONS, not detections.
const RULES = [
  { id: 'R-001', name: 'SSH brute force', logic: '≥ 5 failed logins from one IP within 2 minutes', mitre: 'T1110' },
  { id: 'R-002', name: 'Successful login after failures', logic: 'Success following a brute-force burst from the same IP', mitre: 'T1110 / T1078' },
  { id: 'R-003', name: 'Web path traversal', logic: 'Request path contains ../ or encoded variants', mitre: 'T1190' },
  { id: 'R-004', name: 'SQL injection pattern', logic: "Query string matches common SQLi tokens (' OR 1=1, UNION SELECT)", mitre: 'T1190' },
  { id: 'R-005', name: 'Web scanning / enumeration', logic: '≥ 20 HTTP 404 responses to one IP within 1 minute', mitre: 'T1595' },
]

const RULE_COLUMNS = [
  { key: 'id', label: 'Rule' },
  { key: 'name', label: 'Name' },
  { key: 'logic', label: 'Detection logic' },
  { key: 'mitre', label: 'MITRE ATT&CK', render: (r) => <code className="font-mono text-soc-accent">{r.mitre}</code> },
  { key: 'state', label: 'State', render: () => <PlannedBadge phase={6} /> },
]

const UPLOAD_COLUMNS = [
  { key: 'name', label: 'File' },
  { key: 'type', label: 'Type' },
  { key: 'size', label: 'Size' },
  { key: 'sha256', label: 'SHA-256' },
  { key: 'events', label: 'Events parsed' },
  { key: 'alerts', label: 'Alerts raised' },
]

export default function LogsPage() {
  return (
    <>
      <PageHeader
        title="Log Analysis"
        description="Import log files and packet captures, parse them into events and apply detection rules."
      />

      <PlaceholderNotice phase={6}>
        Uploading and parsing are not built yet. The rules below are planned definitions. None
        of them has run, so no detections are shown.
      </PlaceholderNotice>

      <div className="grid gap-6 lg:grid-cols-5">
        <Card title="Upload file" icon={Upload} className="lg:col-span-2">
          <div
            className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed border-soc-border bg-soc-bg px-4 py-10 text-center opacity-60"
            aria-disabled="true"
          >
            <Upload className="h-8 w-8 text-soc-muted" aria-hidden="true" />
            <p className="mt-3 text-sm font-medium">Drag a file here or browse</p>
            <p className="mt-1 text-xs text-soc-muted">Upload is disabled until Phase 6</p>
          </div>
        </Card>

        <Card title="Supported formats" icon={FileSearch} className="lg:col-span-3">
          <ul className="divide-y divide-soc-border text-sm">
            {FORMATS.map((f) => (
              <li key={f.type} className="flex flex-col gap-1 py-2.5 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="font-medium">{f.type}</p>
                  <p className="text-xs text-soc-muted">{f.example}</p>
                </div>
                <div className="flex gap-3 text-xs text-soc-muted">
                  <code className="font-mono">{f.ext}</code>
                  <span>max {f.limit}</span>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <Card title="Detection rules" icon={ListChecks} className="mt-6">
        <DataTable caption="Detection rules" columns={RULE_COLUMNS} rows={RULES} />
      </Card>

      <Card title="Analysed files" icon={Files} className="mt-6">
        <DataTable
          caption="Analysed files"
          columns={UPLOAD_COLUMNS}
          empty={<EmptyState icon={Files} title="No files analysed" />}
        />
      </Card>
    </>
  )
}
