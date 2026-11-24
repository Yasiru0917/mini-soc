// Settings - users, scan scope, integrations, roles.
//
// Role-based access control (RBAC): each user has ONE role, and each role
// allows a fixed set of actions. The backend checks the role on every
// request. Hiding a button in the UI is convenience, not security.
import { ShieldCheck, Plug, Users, Check, Minus, UserCog, Radar, KeyRound, ScrollText } from 'lucide-react'
import WazuhPanel from '../components/WazuhPanel.jsx'
import ChangePassword from '../components/ChangePassword.jsx'
import AuditLog from '../components/AuditLog.jsx'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import UserManagement from '../components/UserManagement.jsx'
import ScopeEditor from '../components/ScopeEditor.jsx'
import IntegrationStatus from '../components/IntegrationStatus.jsx'
import { useAuth } from '../auth/AuthContext.jsx'

const ROLES = ['Admin', 'Analyst', 'Viewer']
const PERMISSIONS = [
  { action: 'View dashboard, alerts, incidents, scans', allowed: [true, true, true] },
  { action: 'Triage alerts, manage incidents, add evidence', allowed: [true, true, false] },
  { action: 'Upload logs, run authorized scans, threat-intel lookups', allowed: [true, true, false] },
  { action: 'Change scan scope', allowed: [true, false, false] },
  { action: 'Manage users and roles', allowed: [true, false, false] },
]

export default function SettingsPage() {
  const { hasRole } = useAuth()
  const isAdmin = hasRole('admin')

  return (
    <>
      <PageHeader title="Settings" description="Application, integration and access configuration." />

      <Card title="My account" icon={KeyRound} className="mb-6">
        <ChangePassword />
      </Card>

      <Card title="User accounts" icon={UserCog} className="mb-6">
        {isAdmin ? (
          <UserManagement />
        ) : (
          <p className="text-sm text-soc-muted">
            Only administrators can manage user accounts. Ask an admin if you need a different role.
          </p>
        )}
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Authorized scan scope" icon={ShieldCheck}>
          <ScopeEditor />
        </Card>

        <Card title="Integrations" icon={Plug}>
          <IntegrationStatus />
          <p className="mt-3 text-xs text-soc-muted">
            Integration credentials and API keys are read from <code className="font-mono">backend/.env</code> on the
            server. They are never sent to the browser.
          </p>
        </Card>
      </div>

      <Card title="Wazuh SIEM" icon={Radar} className="mt-6">
        <WazuhPanel />
      </Card>

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

      {isAdmin && (
        <Card title="Audit log" icon={ScrollText} className="mt-6">
          <AuditLog />
        </Card>
      )}
    </>
  )
}
