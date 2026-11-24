// Results for one analysed file: rule hits / alerts, plus either the parsed
// events (text logs) or traffic statistics (packet captures).
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Bell, ListOrdered, Network, Globe, MessagesSquare, BarChart3 } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'
import ErrorPanel from '../components/ErrorPanel.jsx'
import Pagination from '../components/Pagination.jsx'
import { SeverityBadge, StatusBadge } from '../components/Badges.jsx'
import { useApi } from '../hooks/useApi.js'
import { qs } from '../api/client.js'
import { formatBytes, formatDate } from '../utils/format.js'

const EVENT_TYPES = ['auth_failure', 'auth_success', 'invalid_user', 'http_request']
const LIMIT = 50

function Stat({ label, value }) {
  return (
    <div className="rounded-lg border border-soc-border bg-soc-bg p-3">
      <dt className="text-xs text-soc-muted">{label}</dt>
      <dd className="mt-1 font-mono text-xl">{value ?? '—'}</dd>
    </div>
  )
}

function Bars({ rows }) {
  const max = Math.max(1, ...rows.map((r) => r[1]))
  return (
    <ul className="space-y-1.5">
      {rows.map(([label, n]) => (
        <li key={label} className="grid grid-cols-[minmax(0,10rem)_1fr_auto] items-center gap-3 text-sm">
          <span className="truncate font-mono text-xs" title={label}>{label}</span>
          <span className="h-2 rounded-full bg-soc-accent/70" style={{ width: `${(n / max) * 100}%`, minWidth: '4px' }} aria-hidden="true" />
          <span className="font-mono text-xs">{n}</span>
        </li>
      ))}
    </ul>
  )
}

function EventsTable({ uploadId }) {
  const [filters, setFilters] = useState({ event_type: '', src_ip: '' })
  const [offset, setOffset] = useState(0)
  const { data, loading } = useApi(`/logs/${uploadId}/events${qs({ ...filters, limit: LIMIT, offset })}`)
  const columns = [
    { key: 'line_no', label: 'Line', render: (e) => <span className="font-mono">{e.line_no}</span> },
    { key: 'timestamp', label: 'Time (UTC)', render: (e) => (e.timestamp ? new Date(e.timestamp).toISOString().replace('T', ' ').slice(0, 19) : '—') },
    { key: 'event_type', label: 'Event' },
    { key: 'src_ip', label: 'Source IP', render: (e) => <code className="font-mono text-xs">{e.src_ip ?? '—'}</code> },
    { key: 'user', label: 'User', render: (e) => e.user ?? '—' },
    { key: 'detail', label: 'Detail', render: (e) => <span className="block max-w-md truncate font-mono text-xs" title={e.detail}>{e.detail}</span> },
  ]
  return (
    <Card title={`Parsed events (${data?.total ?? '…'})`} icon={ListOrdered} className="mt-6">
      <div className="mb-3 grid gap-3 sm:grid-cols-3">
        <select className="input" aria-label="Event type" value={filters.event_type}
          onChange={(e) => { setFilters({ ...filters, event_type: e.target.value }); setOffset(0) }}>
          <option value="">All event types</option>
          {EVENT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <input className="input font-mono" placeholder="Filter by source IP" aria-label="Source IP filter" maxLength={45}
          value={filters.src_ip} onChange={(e) => { setFilters({ ...filters, src_ip: e.target.value.trim() }); setOffset(0) }} />
      </div>
      <DataTable caption="Parsed events" columns={columns} rows={data?.items ?? []} rowKey="line_no"
        empty={<EmptyState icon={ListOrdered} title={loading ? 'Loading…' : 'No events'} />} />
      <Pagination total={data?.total} limit={LIMIT} offset={offset} onChange={setOffset} />
    </Card>
  )
}

export default function LogUploadPage() {
  const { id } = useParams()
  const { data: up, error, loading, reload } = useApi(`/logs/${id}`)

  if (error) return <ErrorPanel error={error} onRetry={reload} />
  if (loading || !up) return <p className="text-sm text-soc-muted">Loading…</p>

  const s = up.summary ?? {}
  const isPcap = up.log_type === 'pcap'
  const alertColumns = [
    { key: 'severity', label: 'Severity', render: (a) => <SeverityBadge severity={a.severity} /> },
    { key: 'rule', label: 'Rule', render: (a) => <code className="font-mono">{a.detection_rule_id}</code> },
    { key: 'title', label: 'Alert', render: (a) => <Link className="hover:text-soc-accent" to={`/alerts/${a.id}`}>{a.title}</Link> },
    { key: 'status', label: 'Status', render: (a) => <StatusBadge status={a.status} /> },
    { key: 'detected_at', label: 'Activity time', render: (a) => formatDate(a.detected_at) },
  ]

  return (
    <>
      <Link to="/logs" className="mb-4 inline-flex items-center gap-1 text-sm text-soc-muted hover:text-soc-text">
        <ArrowLeft className="h-4 w-4" aria-hidden="true" /> All files
      </Link>
      <PageHeader title={up.original_name}
        description={`Upload #${up.id} · analysed ${formatDate(up.created_at)} by ${up.uploaded_by ?? '?'}`} />
      <p className="-mt-4 mb-6 break-all font-mono text-xs text-soc-muted">SHA-256 {up.sha256}</p>

      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Format" value={isPcap ? 'pcap' : up.log_type} />
        <Stat label="Size" value={formatBytes(up.size_bytes)} />
        {isPcap ? (
          <>
            <Stat label="Packets" value={s.packets} />
            <Stat label="Duration" value={s.duration_seconds != null ? `${s.duration_seconds}s` : null} />
          </>
        ) : (
          <>
            <Stat label="Events parsed" value={up.events_parsed} />
            <Stat label="Lines skipped" value={up.lines_skipped} />
          </>
        )}
      </dl>

      <Card title={`Alerts raised (${up.alerts.length})`} icon={Bell} className="mt-6">
        <DataTable caption="Alerts from this file" columns={alertColumns} rows={up.alerts}
          empty={<EmptyState icon={Bell} title="No rule matched">No detection rule fired on this file.</EmptyState>} />
      </Card>

      {isPcap ? (
        <div className="mt-6 grid gap-6 lg:grid-cols-2">
          <Card title="Protocols" icon={BarChart3}>
            {s.protocols?.length ? <Bars rows={s.protocols} /> : <EmptyState title="No packets" />}
          </Card>
          <Card title="Top talkers (by packets sent)" icon={Network}>
            {s.top_talkers?.length ? <Bars rows={s.top_talkers.map((t) => [t.ip, t.packets])} /> : <EmptyState title="No IP traffic" />}
          </Card>
          <Card title="Conversations" icon={MessagesSquare}>
            <DataTable caption="Conversations" rowKey="key" rows={(s.conversations ?? []).map((c) => ({ ...c, key: `${c.a}-${c.b}` }))}
              columns={[
                { key: 'a', label: 'Host A', render: (c) => <code className="font-mono text-xs">{c.a}</code> },
                { key: 'b', label: 'Host B', render: (c) => <code className="font-mono text-xs">{c.b}</code> },
                { key: 'packets', label: 'Packets' },
                { key: 'bytes', label: 'Bytes', render: (c) => formatBytes(c.bytes) },
              ]} empty={<EmptyState title="No conversations" />} />
          </Card>
          <Card title="DNS queries" icon={Globe}>
            {s.dns_queries?.length ? <Bars rows={s.dns_queries} /> : <EmptyState title="No DNS queries" />}
            <p className="mt-3 text-xs text-soc-muted">Analysed with name resolution disabled: no lookups were made for these domains.</p>
          </Card>
        </div>
      ) : (
        <EventsTable uploadId={up.id} />
      )}
    </>
  )
}
