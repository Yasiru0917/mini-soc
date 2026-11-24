// Network Scanning - discover devices, open ports and services with Nmap.
//
// How it will work (Phase 5):
//  1. The analyst picks a target and a PRESET scan profile (no free-text flags).
//  2. The backend checks the target is inside the authorized scope.
//     Anything outside it is rejected and written to the audit log.
//  3. Nmap runs in the background; its XML output is parsed into
//     device / port / service records.
//
// The form below is visible but disabled, so the design is reviewable
// without pretending that scans work.
import { Radar, ShieldCheck, History, Server } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import PlaceholderNotice from '../components/PlaceholderNotice.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'
import { DEFAULT_SCAN_SCOPE } from '../config/appConfig.js'

// Preset profiles. -sT (TCP connect) works without Administrator rights on
// Windows; -sS (SYN scan) would need admin, so it is not a default.
const SCAN_PROFILES = [
  { id: 'discovery', label: 'Host discovery', flags: '-sn', about: 'Which hosts are up? No port scan.' },
  { id: 'quick', label: 'Quick TCP (top 100 ports)', flags: '-sT --top-ports 100', about: 'Fast check of common ports.' },
  { id: 'service', label: 'Service & version detection', flags: '-sT -sV --top-ports 1000', about: 'Identify software versions on open ports.' },
]

const DEVICE_COLUMNS = [
  { key: 'ip', label: 'IP address' },
  { key: 'hostname', label: 'Hostname' },
  { key: 'mac', label: 'MAC / vendor' },
  { key: 'ports', label: 'Open ports' },
  { key: 'services', label: 'Services' },
  { key: 'last_seen', label: 'Last seen' },
]

const SCAN_COLUMNS = [
  { key: 'target', label: 'Target' },
  { key: 'profile', label: 'Profile' },
  { key: 'requested_by', label: 'Requested by' },
  { key: 'status', label: 'Status' },
  { key: 'started', label: 'Started' },
]

export default function NetworkPage() {
  return (
    <>
      <PageHeader
        title="Network Scanning"
        description="Discover hosts, open ports and running services on authorized lab networks using Nmap."
      />

      <PlaceholderNotice phase={5}>
        Scanning is not connected. The form is shown for design review only. No scans can run.
      </PlaceholderNotice>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="New scan" icon={Radar} className="lg:col-span-2">
          <form className="grid gap-4 sm:grid-cols-2" onSubmit={(e) => e.preventDefault()}>
            <div>
              <label htmlFor="target" className="label">Target (IP or CIDR)</label>
              <input id="target" className="input font-mono" placeholder="192.168.56.101" disabled />
            </div>
            <div>
              <label htmlFor="profile" className="label">Scan profile</label>
              <select id="profile" className="input" disabled>
                {SCAN_PROFILES.map((p) => (
                  <option key={p.id}>{p.label}</option>
                ))}
              </select>
            </div>
            <div className="sm:col-span-2">
              <button type="submit" className="btn-primary" disabled title="Available in Phase 5">
                <Radar className="h-4 w-4" aria-hidden="true" /> Start scan
              </button>
            </div>
          </form>

          <ul className="mt-5 grid gap-2 sm:grid-cols-3">
            {SCAN_PROFILES.map((p) => (
              <li key={p.id} className="rounded-lg border border-soc-border bg-soc-bg p-3">
                <p className="text-sm font-medium">{p.label}</p>
                <code className="mt-1 block font-mono text-xs text-soc-accent">nmap {p.flags}</code>
                <p className="mt-1 text-xs text-soc-muted">{p.about}</p>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Authorized scope" icon={ShieldCheck}>
          <p className="font-mono text-lg text-soc-accent">{DEFAULT_SCAN_SCOPE}</p>
          <p className="mt-1 text-xs text-soc-muted">VirtualBox host-only lab network (default)</p>
          <ul className="mt-4 list-disc space-y-1.5 pl-4 text-xs text-soc-muted">
            <li>Targets outside the scope will be rejected by the server.</li>
            <li>Public internet addresses are never scanned by default.</li>
            <li>Every scan request is recorded in an audit log.</li>
            <li>Only admins can change the scope.</li>
          </ul>
        </Card>
      </div>

      <Card title="Discovered devices" icon={Server} className="mt-6">
        <DataTable
          caption="Discovered devices"
          columns={DEVICE_COLUMNS}
          empty={<EmptyState icon={Server} title="No devices discovered">Run an authorized scan (Phase 5) to populate the inventory.</EmptyState>}
        />
      </Card>

      <Card title="Scan history" icon={History} className="mt-6">
        <DataTable
          caption="Scan history"
          columns={SCAN_COLUMNS}
          empty={<EmptyState icon={History} title="No scans yet" />}
        />
      </Card>
    </>
  )
}
