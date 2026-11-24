// Log Analysis - upload log files / packet captures and run detection rules.
//
// What happens on upload (server side):
//  1. Size, extension and CONTENT are checked (a .pcap must really be a pcap).
//  2. The file is stored under a random name; its SHA-256 is recorded.
//  3. A parser turns lines into normalised events (or TShark summarises packets).
//  4. Detection rules run; each hit becomes an alert naming the rule and file.
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Upload, ListChecks, Files, FileSearch } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'
import ErrorPanel from '../components/ErrorPanel.jsx'
import Pagination from '../components/Pagination.jsx'
import { SeverityBadge } from '../components/Badges.jsx'
import { apiFetch } from '../api/client.js'
import { useApi } from '../hooks/useApi.js'
import { useAuth } from '../auth/AuthContext.jsx'
import { formatBytes, formatDate } from '../utils/format.js'

const TYPES = [
  { id: 'auto', label: 'Auto-detect' },
  { id: 'auth', label: 'Linux auth.log' },
  { id: 'access', label: 'Web access log (Apache/Nginx)' },
  { id: 'jsonl', label: 'JSON lines' },
  { id: 'pcap', label: 'Packet capture (.pcap/.pcapng)' },
]
const TYPE_LABEL = { auth: 'auth.log', access: 'Access log', jsonl: 'JSON lines', pcap: 'Packet capture' }
const LIMIT = 20

function UploadForm({ onDone }) {
  const [file, setFile] = useState(null)
  const [logType, setLogType] = useState('auto')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  async function submit(e) {
    e.preventDefault()
    const form = new FormData()
    form.append('file', file)
    form.append('log_type', logType)
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      const upload = await apiFetch('/logs/upload', { method: 'POST', body: form })
      setResult(upload)
      setFile(null)
      e.target.reset()
      onDone()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3">
      <label htmlFor="log-file" className="flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-soc-border bg-soc-bg px-4 py-8 text-center hover:border-soc-accent/50">
        <Upload className="h-7 w-7 text-soc-muted" aria-hidden="true" />
        <span className="mt-2 text-sm font-medium">{file ? file.name : 'Choose a log file or packet capture'}</span>
        <span className="mt-1 text-xs text-soc-muted">{file ? formatBytes(file.size) : 'Logs up to 10 MB · pcap up to 50 MB'}</span>
        <input id="log-file" type="file" className="sr-only" accept=".log,.txt,.json,.jsonl,.pcap,.pcapng,.cap"
          onChange={(e) => setFile(e.target.files[0] ?? null)} />
      </label>
      <div>
        <label htmlFor="log-type" className="label">Format</label>
        <select id="log-type" className="input" value={logType} onChange={(e) => setLogType(e.target.value)}>
          {TYPES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
        </select>
      </div>
      <button type="submit" className="btn-primary w-full" disabled={!file || busy}>
        {busy ? 'Analysing…' : 'Upload & analyse'}
      </button>
      {error && <p role="alert" className="text-sm text-rose-300">{error}</p>}
      {result && (
        <p role="status" className="text-sm text-emerald-400">
          Analysed <Link className="underline" to={`/logs/${result.id}`}>{result.original_name}</Link>:{' '}
          {result.events_parsed} {result.log_type === 'pcap' ? 'packets' : 'events'}, {result.alerts_raised} alert(s).
        </p>
      )}
    </form>
  )
}

export default function LogsPage() {
  const { hasRole } = useAuth()
  const [offset, setOffset] = useState(0)
  const uploads = useApi(`/logs?limit=${LIMIT}&offset=${offset}`)
  const { data: rules } = useApi('/logs/rules')

  const uploadColumns = [
    { key: 'name', label: 'File', render: (u) => <Link className="font-medium hover:text-soc-accent" to={`/logs/${u.id}`}>{u.original_name}</Link> },
    { key: 'type', label: 'Type', render: (u) => TYPE_LABEL[u.log_type] ?? u.log_type },
    { key: 'size', label: 'Size', render: (u) => formatBytes(u.size_bytes) },
    { key: 'events', label: 'Events / packets', render: (u) => u.events_parsed },
    { key: 'alerts', label: 'Alerts', render: (u) => <span className={u.alerts_raised ? 'font-semibold text-sev-high' : ''}>{u.alerts_raised}</span> },
    { key: 'sha256', label: 'SHA-256', render: (u) => <code className="font-mono text-[11px] text-soc-muted" title={u.sha256}>{u.sha256.slice(0, 16)}…</code> },
    { key: 'by', label: 'By', render: (u) => u.uploaded_by },
    { key: 'at', label: 'Analysed', render: (u) => formatDate(u.created_at) },
  ]

  const ruleColumns = [
    { key: 'id', label: 'Rule', render: (r) => <code className="font-mono">{r.id}</code> },
    { key: 'name', label: 'Name' },
    { key: 'logic', label: 'Detection logic', render: (r) => <span className="whitespace-normal">{r.logic}</span> },
    { key: 'mitre', label: 'MITRE ATT&CK', render: (r) => <code className="font-mono text-soc-accent">{r.mitre}</code> },
    { key: 'severity', label: 'Severity', render: (r) => <SeverityBadge severity={r.severity} /> },
    { key: 'applies', label: 'Input', render: (r) => (r.applies_to === 'pcap' ? 'Packet capture' : 'Text logs') },
  ]

  return (
    <>
      <PageHeader
        title="Log Analysis"
        description="Import log files and packet captures, parse them into events and apply transparent detection rules."
      />
      {uploads.error && <ErrorPanel error={uploads.error} onRetry={uploads.reload} />}

      <div className="grid gap-6 lg:grid-cols-5">
        <Card title="Upload file" icon={Upload} className="lg:col-span-2">
          {hasRole('analyst') ? (
            <UploadForm onDone={uploads.reload} />
          ) : (
            <p className="text-sm text-soc-muted">Only analysts and admins can upload files.</p>
          )}
        </Card>

        <Card title="Supported formats" icon={FileSearch} className="lg:col-span-3">
          <ul className="divide-y divide-soc-border text-sm">
            {[
              ['Linux auth log', '/var/log/auth.log (sshd)', '.log .txt', '10 MB'],
              ['Web access log', 'Apache / Nginx combined or common format', '.log .txt', '10 MB'],
              ['JSON lines', 'One object per line: timestamp, event_type, src_ip, user, path, status', '.json .jsonl', '10 MB'],
              ['Packet capture', 'Saved from Wireshark / tcpdump; analysed with TShark', '.pcap .pcapng', '50 MB'],
            ].map(([type, example, ext, limit]) => (
              <li key={type} className="flex flex-col gap-1 py-2.5 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="font-medium">{type}</p>
                  <p className="text-xs text-soc-muted">{example}</p>
                </div>
                <div className="flex shrink-0 gap-3 text-xs text-soc-muted">
                  <code className="font-mono">{ext}</code><span>max {limit}</span>
                </div>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-soc-muted">
            Sample files to try are in the repository's <code className="font-mono">samples/</code> folder.
            They are synthetic and use documentation-only IP addresses.
          </p>
        </Card>
      </div>

      <Card title="Analysed files" icon={Files} className="mt-6">
        <DataTable caption="Analysed files" columns={uploadColumns} rows={uploads.data?.items ?? []}
          empty={<EmptyState icon={Files} title={uploads.loading ? 'Loading…' : 'No files analysed yet'} />} />
        <Pagination total={uploads.data?.total} limit={LIMIT} offset={offset} onChange={setOffset} />
      </Card>

      <Card title="Detection rules" icon={ListChecks} className="mt-6">
        <DataTable caption="Detection rules" columns={ruleColumns} rows={rules ?? []} />
        <p className="mt-3 text-xs text-soc-muted">
          These are the rules running in the backend (<code className="font-mono">app/detection/rules.py</code>), listed
          live from the API.
        </p>
      </Card>
    </>
  )
}
