// "Change my password". Needs the current password; signs out other sessions.
import { useState } from 'react'
import { apiFetch } from '../api/client.js'

const EMPTY = { current_password: '', new_password: '', confirm: '' }

export default function ChangePassword() {
  const [form, setForm] = useState(EMPTY)
  const [message, setMessage] = useState(null)
  const [busy, setBusy] = useState(false)
  const set = (f) => (e) => setForm({ ...form, [f]: e.target.value })
  const mismatch = form.confirm && form.confirm !== form.new_password

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setMessage(null)
    try {
      await apiFetch('/auth/change-password', {
        method: 'POST', body: { current_password: form.current_password, new_password: form.new_password },
      })
      setForm(EMPTY)
      setMessage({ ok: true, text: 'Password changed. Other sessions have been signed out.' })
    } catch (err) {
      setMessage({ ok: false, text: err.message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="grid gap-3 sm:grid-cols-3" noValidate>
      <div>
        <label htmlFor="cp-current" className="label">Current password</label>
        <input id="cp-current" type="password" className="input" autoComplete="current-password" maxLength={128}
          value={form.current_password} onChange={set('current_password')} />
      </div>
      <div>
        <label htmlFor="cp-new" className="label">New password (12+ chars)</label>
        <input id="cp-new" type="password" className="input" autoComplete="new-password" minLength={12} maxLength={128}
          value={form.new_password} onChange={set('new_password')} />
      </div>
      <div>
        <label htmlFor="cp-confirm" className="label">Repeat new password</label>
        <input id="cp-confirm" type="password" className="input" autoComplete="new-password" maxLength={128}
          value={form.confirm} onChange={set('confirm')} aria-invalid={mismatch || undefined} />
      </div>
      <div className="sm:col-span-3">
        {mismatch && <p className="mb-2 text-sm text-rose-300">The new passwords don't match.</p>}
        {message && <p role="status" className={`mb-2 text-sm ${message.ok ? 'text-emerald-400' : 'text-rose-300'}`}>{message.text}</p>}
        <button type="submit" className="btn-primary"
          disabled={busy || !form.current_password || form.new_password.length < 12 || form.new_password !== form.confirm}>
          Change password
        </button>
      </div>
    </form>
  )
}
