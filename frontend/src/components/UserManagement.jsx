// Admin-only user management: list users, create accounts, change role,
// enable/disable. The server re-checks the admin role on every call, and
// refuses to let an admin demote or disable their own account.
import { useState } from 'react'
import { UserPlus } from 'lucide-react'
import { apiFetch } from '../api/client.js'
import { useApi } from '../hooks/useApi.js'
import { useAuth } from '../auth/AuthContext.jsx'
import DataTable from './DataTable.jsx'
import ErrorPanel from './ErrorPanel.jsx'
import EmptyState from './EmptyState.jsx'

const ROLES = ['viewer', 'analyst', 'admin']
const EMPTY_FORM = { username: '', password: '', role: 'analyst' }

function formatDate(iso) {
  return iso ? new Date(iso).toLocaleString() : 'Never'
}

export default function UserManagement() {
  const { user: me } = useAuth()
  const { data: users, error, loading, reload } = useApi('/users')
  const [form, setForm] = useState(EMPTY_FORM)
  const [formError, setFormError] = useState(null)
  const [actionError, setActionError] = useState(null)
  const [busy, setBusy] = useState(false)

  async function createUser(e) {
    e.preventDefault()
    setFormError(null)
    setBusy(true)
    try {
      await apiFetch('/users', { method: 'POST', body: form })
      setForm(EMPTY_FORM)
      reload()
    } catch (err) {
      setFormError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function updateUser(id, changes) {
    setActionError(null)
    try {
      await apiFetch(`/users/${id}`, { method: 'PATCH', body: changes })
      reload()
    } catch (err) {
      setActionError(err)
    }
  }

  const columns = [
    { key: 'username', label: 'Username', render: (u) => <span className="font-medium">{u.username}{u.id === me.id && <span className="ml-2 text-xs text-soc-muted">(you)</span>}</span> },
    {
      key: 'role',
      label: 'Role',
      render: (u) => (
        <select
          className="input w-32 py-1"
          value={u.role}
          disabled={u.id === me.id}
          aria-label={`Role for ${u.username}`}
          onChange={(e) => updateUser(u.id, { role: e.target.value })}
        >
          {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
      ),
    },
    {
      key: 'is_active',
      label: 'Status',
      render: (u) => (
        <button
          type="button"
          className="btn-secondary px-2.5 py-1 text-xs"
          disabled={u.id === me.id}
          onClick={() => updateUser(u.id, { is_active: !u.is_active })}
        >
          <span className={`h-2 w-2 rounded-full ${u.is_active ? 'bg-emerald-400' : 'bg-soc-muted'}`} aria-hidden="true" />
          {u.is_active ? 'Active' : 'Disabled'}
        </button>
      ),
    },
    { key: 'last_login_at', label: 'Last login', render: (u) => formatDate(u.last_login_at) },
    { key: 'created_at', label: 'Created', render: (u) => formatDate(u.created_at) },
    {
      key: 'reset', label: '',
      render: (u) => u.id !== me.id && (
        <button type="button" className="text-xs text-soc-accent hover:underline" onClick={() => resetPassword(u)}>
          Reset password
        </button>
      ),
    },
  ]

  async function resetPassword(u) {
    const pw = window.prompt(`New password for ${u.username} (12+ characters). Share it with them securely.`)
    if (!pw) return
    setActionError(null)
    try {
      await apiFetch(`/users/${u.id}/reset-password`, { method: 'POST', body: { new_password: pw } })
      window.alert(`Password for ${u.username} was reset. They have been signed out everywhere.`)
    } catch (err) {
      setActionError(err)
    }
  }

  return (
    <div className="space-y-6">
      {error && <ErrorPanel error={error} onRetry={reload} />}
      {actionError && <ErrorPanel error={actionError} />}

      <DataTable
        caption="User accounts"
        columns={columns}
        rows={users ?? []}
        empty={<EmptyState title={loading ? 'Loading…' : 'No users'} />}
      />

      <form onSubmit={createUser} className="rounded-lg border border-soc-border bg-soc-bg p-4" noValidate>
        <p className="mb-3 flex items-center gap-2 text-sm font-semibold">
          <UserPlus className="h-4 w-4 text-soc-accent" aria-hidden="true" /> Create account
        </p>
        {formError && <p role="alert" className="mb-3 text-sm text-rose-300">{formError}</p>}
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <label htmlFor="new-username" className="label">Username</label>
            <input id="new-username" className="input" autoComplete="off" required maxLength={32}
              pattern="[a-zA-Z0-9._-]{3,32}" value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })} />
          </div>
          <div>
            <label htmlFor="new-password" className="label">Password (12+ chars)</label>
            <input id="new-password" type="password" className="input" autoComplete="new-password" required
              minLength={12} maxLength={128} value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })} />
          </div>
          <div>
            <label htmlFor="new-role" className="label">Role</label>
            <select id="new-role" className="input" value={form.role}
              onChange={(e) => setForm({ ...form, role: e.target.value })}>
              {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
          <div className="flex items-end">
            <button type="submit" className="btn-primary w-full" disabled={busy || !form.username || !form.password}>
              {busy ? 'Creating…' : 'Create user'}
            </button>
          </div>
        </div>
        <p className="mt-2 text-xs text-soc-muted">
          Usernames: 3–32 letters, digits, dot, dash or underscore. Changing a role or disabling an
          account signs that user out everywhere.
        </p>
      </form>
    </div>
  )
}
