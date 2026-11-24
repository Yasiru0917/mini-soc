// Settings - scan scope, integrations, users and roles.
//
// Role-based access control (RBAC): each user has ONE role, and each role
// allows a fixed set of actions. The backend checks the role on every
// request (Phase 3). Hiding a button in the UI is convenience, not security.
import { ShieldCheck, Plug, Users, Check, Minus } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import PlaceholderNotice from '../components/PlaceholderNotice.jsx'
import Card from '../components/Card.jsx'
import { PlannedBadge } from '../components/Badges.jsx'
import { DEFAULT_SCAN_SCOPE } from '../config/appConfig.js'

const INTEGRATIONS = [
  { name: 'Nmap', purpose: 'Network discovery and port scanning', phase: 5 },
  { name: 'TShark (Wireshark)', purpose: 'Packet capture analysis', phase: 6 },
  { name: 'Wazuh', purpose: 'SIEM alerts from monitored endpoints', phase: 7 },
  { name: 'Threat intelligence APIs', purpose: 'AbuseIPDB, VirusTotal, OTX', phase: 8 },
]

const ROLES = ['Admin', 'Analyst', 'Viewer']
const PERMISSIONS = [
  { action: 'View dashboard, alerts, incidents', allowed: [true, true, true] },
  { action: 'Triage alerts, manage incidents', allowed: [true, true, false] },
  { action: 'Upload logs, run authorized scans', allowed: [true, true, false] },
  { action: 'Change scan scope and integrations', allowed: [true, false, false] },
  { action: 'Manage users and roles', allowed: [true, false, false] },
]

export default function SettingsPage() {
  return (
    <>
      <PageHeader title="Settings" description="Application, integration and access configuration." />

      <PlaceholderNotice phase={3}>
        Settings are read-only. Saving configuration and managing users require the backend.
      </PlaceholderNotice>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Authorized scan scope" icon={ShieldCheck}>
          <label htmlFor="scope" className="label">Allowed networks (CIDR)</label>
          <input id="scope" className="input font-mono" value={DEFAULT_SCAN_SCOPE} readOnly disabled />
          <p className="mt-2 text-xs text-soc-muted">
            Default: VirtualBox host-only network. Only add networks you own or have written
            permission to test.
          </p>
        </Card>

        <Card title="Integrations" icon={Plug}>
          <ul className="divide-y divide-soc-border">
            {INTEGRATIONS.map((i) => (
              <li key={i.name} className="flex items-center justify-between gap-3 py-2.5">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{i.name}</p>
                  <p className="text-xs text-soc-muted">{i.purpose}</p>
                </div>
                <PlannedBadge phase={i.phase} />
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <Card title="Roles and permissions" icon={Users} className="mt-6">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[480px] text-sm">
            <caption className="sr-only">Role permissions</caption>
            <thead>
              <tr className="border-b border-soc-border text-xs uppercase tracking-wider text-soc-muted">
                <th scope="col" className="px-3 py-2 text-left font-medium">Action</th>
                {ROLES.map((r) => <th key={r} scope="col" className="px-3 py-2 font-medium">{r}</th>)}
              </tr>
            </thead>
            <tbody>
              {PERMISSIONS.map((p) => (
                <tr key={p.action} className="border-b border-soc-border/60">
                  <td className="px-3 py-2.5">{p.action}</td>
                  {p.allowed.map((ok, i) => (
                    <td key={ROLES[i]} className="px-3 py-2.5 text-center">
                      {ok
                        ? <Check className="mx-auto h-4 w-4 text-emerald-400" aria-label="Allowed" />
                        : <Minus className="mx-auto h-4 w-4 text-soc-muted" aria-label="Not allowed" />}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}
