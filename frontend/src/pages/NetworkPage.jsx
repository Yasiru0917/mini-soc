// Network Scanning - discover devices, open ports and services with Nmap.
//
// How it works:
//  1. Pick a target inside the authorized scope and a PRESET profile.
//  2. The server re-checks the scope (and audits the request), then runs
//     Nmap in the background. This page polls until the scan finishes.
//  3. Results update the device inventory; risky exposed services raise
//     alerts (rule NMAP-RISKY-PORT) that link back to the scan.
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Radar, ShieldCheck, History, Server, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'
import ErrorPanel from '../components/ErrorPanel.jsx'
import { apiFetch } from '../api/client.js'
import { useApi } from '../hooks/useApi.js'
import { useAuth } from '../auth/AuthContext.jsx'
import { scopeCheck } from '../utils/cidr.js'
import { formatDate } from '../utils/format.js'

const STATUS_STYLE = {
  queued: { icon: Loader2, cls: 'text-soc-muted animate-spin', label: 'Queued' },
  running: { icon: Loader2, cls: 'text-soc-accent animate-spin', label: 'Running' },
  completed: { icon: CheckCircle2, cls: 'text-emerald-400', label: 'Completed' },
  failed: { icon: XCircle, cls: 'text-sev-critical', label: 'Failed' },
}

function ScanStatus({ status }) {
  const s = STATUS_STYLE[status] ?? STATUS_STYLE.failed
  const Icon = s.icon
  return (
    <span className="inline-flex items-center gap-1.5">
      <Icon className={`h-4 w-4 ${s.cls}`} aria-hidden="true" /> {s.label}
    </span>
  )
}

export default function NetworkPage() {
  const { hasRole } = useAuth()
  const canScan = hasRole('analyst')
  const { data: scope } = useApi('/settings/scan-scope')
  const { data: profiles } = useApi('/scans/profiles')
  const scans = useApi('/scans?limit=10')
  const devices = useApi('/devices')

  const [target, setTarget] = useState('192.168.56.1')
  const [profile, setProfile] = useState('quick')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const active = scans.data?.items?.some((s) => s.status === 'queued' || s.status === 'running')
  const { reload: reloadScans } = scans
  const { reload: reloadDevices } = devices

  // While a scan is running, refresh every 2 seconds; refresh devices when it ends.
  useEffect(() => {
    if (!active) return undefined
    const timer = setTimeout(reloadScans, 2000)
    return () => clearTimeout(timer)
  }, [active, scans.data, reloadScans])

  const [wasActive, setWasActive] = useState(false)
  useEffect(() => {
    if (wasActive && !active) reloadDevices()
    setWasActive(Boolean(active))
  }, [active, wasActive, reloadDevices])

  const hint = scope ? scopeCheck(target, scope.cidrs) : null

  async function startScan(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await apiFetch('/scans', { method: 'POST', body: { target: target.trim(), profile } })
      reloadScans()
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  const scanColumns = [
    { key: 'id', label: 'Scan', render: (s) => <span className="font-mono">#{s.id}</span> },
    { key: 'target', label: 'Target', render: (s) => <code className="font-mono">{s.target}</code> },
    { key: 'profile', label: 'Profile' },
    { key: 'status', label: 'Status', render: (s) => <ScanStatus status={s.status} /> },
    { key: 'hosts_up', label: 'Hosts up', render: (s) => s.hosts_up ?? '—' },
    { key: 'open_ports', label: 'Open ports', render: (s) => s.open_ports ?? '—' },
    { key: 'alerts', label: 'Alerts', render: (s) => s.alerts_raised ? <Link className="text-soc-accent" to="/alerts?source=nmap">{s.alerts_raised}</Link> : '0' },
    { key: 'requested_by', label: 'By' },
    { key: 'created_at', label: 'Started', render: (s) => formatDate(s.started_at ?? s.created_at) },
  ]

  const deviceColumns = [
    { key: 'ip', label: 'IP address', render: (d) => <code className="font-mono">{d.ip}</code> },
    { key: 'hostname', label: 'Hostname', render: (d) => d.hostname ?? '—' },
    { key: 'mac', label: 'MAC / vendor', render: (d) => d.mac ? `${d.mac}${d.vendor ? ` (${d.vendor})` : ''}` : '—' },
    {
      key: 'ports', label: 'Open ports / services',
      render: (d) => d.ports.length === 0 ? <span className="text-soc-muted">none found</span> : (
        <div className="flex max-w-xl flex-wrap gap-1">
          {d.ports.map((p) => (
            <span key={`${p.port}/${p.protocol}`} className="rounded border border-soc-border bg-soc-bg px-1.5 py-0.5 font-mono text-[11px]"
              title={[p.product, p.version].filter(Boolean).join(' ') || undefined}>
              {p.port}/{p.protocol} {p.service ?? ''}
            </span>
          ))}
        </div>
      ),
    },
    { key: 'last_seen', label: 'Last seen', render: (d) => formatDate(d.last_seen) },
  ]

  const lastScan = scans.data?.items?.[0]

  return (
    <>
      <PageHeader
        title="Network Scanning"
        description="Discover hosts, open ports and running services on authorized lab networks using Nmap."
      />
      {(scans.error || devices.error) && <ErrorPanel error={scans.error ?? devices.error} onRetry={() => { reloadScans(); reloadDevices() }} />}

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="New scan" icon={Radar} className="lg:col-span-2">
          {canScan ? (
            <form className="grid gap-4 sm:grid-cols-2" onSubmit={startScan}>
              <div>
                <label htmlFor="target" className="label">Target (IP or CIDR, max /24)</label>
                <input id="target" className="input font-mono" value={target} maxLength={64}
                  onChange={(e) => setTarget(e.target.value)} aria-describedby="target-hint" />
                <p id="target-hint" className={`mt-1 text-xs ${hint === 'in' ? 'text-emerald-400' : hint === 'out' ? 'text-rose-300' : 'text-soc-muted'}`}>
                  {hint === 'in' && 'Inside the authorized scope'}
                  {hint === 'out' && 'Outside the authorized scope - the server will refuse it'}
                  {hint === 'invalid' && 'Enter an IPv4 address or CIDR range'}
                </p>
              </div>
              <div>
                <label htmlFor="profile" className="label">Scan profile</label>
                <select id="profile" className="input" value={profile} onChange={(e) => setProfile(e.target.value)}>
                  {(profiles ?? []).map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                </select>
              </div>
              <div className="sm:col-span-2">
                {error && <p role="alert" className="mb-2 text-sm text-rose-300">{error.message}</p>}
                <button type="submit" className="btn-primary" disabled={busy || active || !target.trim()}>
                  <Radar className="h-4 w-4" aria-hidden="true" /> {active ? 'Scan in progress…' : 'Start scan'}
                </button>
              </div>
            </form>
          ) : (
            <p className="text-sm text-soc-muted">Viewers can see results but only analysts and admins can start scans.</p>
          )}

          <ul className="mt-5 grid gap-2 sm:grid-cols-3">
            {(profiles ?? []).map((p) => (
              <li key={p.id} className="rounded-lg border border-soc-border bg-soc-bg p-3">
                <p className="text-sm font-medium">{p.label}</p>
                <code className="mt-1 block font-mono text-xs text-soc-accent">{p.command}</code>
                <p className="mt-1 text-xs text-soc-muted">{p.description}</p>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Authorized scope" icon={ShieldCheck}>
          {(scope?.cidrs ?? []).map((c) => <p key={c} className="font-mono text-lg text-soc-accent">{c}</p>)}
          <p className="mt-1 text-xs text-soc-muted">
            {scope?.is_default ? 'Default: VirtualBox host-only lab network' : `Set by ${scope?.updated_by ?? 'admin'} · ${formatDate(scope?.updated_at)}`}
          </p>
          <ul className="mt-4 list-disc space-y-1.5 pl-4 text-xs text-soc-muted">
            <li>Targets outside the scope are rejected by the server.</li>
            <li>Hostnames are refused; at most a /24 per scan.</li>
            <li>Every request, including refused ones, is in the audit log.</li>
            <li>Only admins can change the scope (Settings).</li>
          </ul>
        </Card>
      </div>

      {lastScan?.status === 'failed' && (
        <div role="alert" className="mt-6 rounded-xl border border-sev-critical/40 bg-sev-critical/10 p-4 text-sm">
          <p className="font-semibold text-rose-200">Scan #{lastScan.id} failed</p>
          <p className="mt-1 break-words font-mono text-xs text-soc-muted">{lastScan.error}</p>
        </div>
      )}

      <Card title={`Device inventory (${devices.data?.length ?? 0})`} icon={Server} className="mt-6">
        <DataTable caption="Discovered devices" columns={deviceColumns} rows={devices.data ?? []}
          empty={<EmptyState icon={Server} title={devices.loading ? 'Loading…' : 'No devices discovered'}>Run an authorized scan to build the inventory.</EmptyState>} />
      </Card>

      <Card title="Scan history" icon={History} className="mt-6">
        <DataTable caption="Scan history" columns={scanColumns} rows={scans.data?.items ?? []}
          empty={<EmptyState icon={History} title={scans.loading ? 'Loading…' : 'No scans yet'} />} />
        {lastScan?.command && (
          <p className="mt-3 break-all font-mono text-[11px] text-soc-muted">Last command: {lastScan.command}</p>
        )}
      </Card>
    </>
  )
}
