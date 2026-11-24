// Admin editor for the authorized scan scope (one CIDR per line).
import { useState } from 'react'
import { apiFetch } from '../api/client.js'
import { useApi } from '../hooks/useApi.js'
import { useAuth } from '../auth/AuthContext.jsx'
import { formatDate } from '../utils/format.js'

export default function ScopeEditor() {
  const { hasRole } = useAuth()
  const isAdmin = hasRole('admin')
  const { data: scope, reload } = useApi('/settings/scan-scope')
  const [text, setText] = useState(null)
  const [allowPublic, setAllowPublic] = useState(false)
  const [message, setMessage] = useState(null)

  const value = text ?? (scope?.cidrs ?? []).join('\n')

  async function save(e) {
    e.preventDefault()
    setMessage(null)
    const cidrs = value.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
    try {
      await apiFetch('/settings/scan-scope', { method: 'PUT', body: { cidrs, allow_public: allowPublic } })
      setText(null)
      setAllowPublic(false)
      setMessage({ ok: true, text: 'Scope saved.' })
      reload()
    } catch (err) {
      setMessage({ ok: false, text: err.message })
    }
  }

  return (
    <form onSubmit={save}>
      <label htmlFor="scope" className="label">Allowed networks (one CIDR per line)</label>
      <textarea id="scope" rows={3} className="input font-mono" value={value} disabled={!isAdmin}
        onChange={(e) => setText(e.target.value)} />
      <p className="mt-2 text-xs text-soc-muted">
        {scope?.is_default ? 'Default: VirtualBox host-only network.' : `Last changed by ${scope?.updated_by ?? '?'} · ${formatDate(scope?.updated_at)}`}
        {' '}Only add networks you own or have written permission to test.
      </p>
      {isAdmin && (
        <>
          <label className="mt-3 flex items-start gap-2 text-xs text-soc-muted">
            <input type="checkbox" className="mt-0.5" checked={allowPublic} onChange={(e) => setAllowPublic(e.target.checked)} />
            I have written permission to scan the non-private ranges listed above.
          </label>
          {message && <p role="status" className={`mt-2 text-sm ${message.ok ? 'text-emerald-400' : 'text-rose-300'}`}>{message.text}</p>}
          <button type="submit" className="btn-primary mt-3" disabled={text === null}>Save scope</button>
        </>
      )}
    </form>
  )
}
