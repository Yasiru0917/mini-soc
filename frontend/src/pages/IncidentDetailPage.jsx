// One incident: the analyst's workspace.
// Status workflow, assignment, linked alerts, notes timeline, evidence with
// SHA-256 hashes, and the resolution / recommendations write-up.
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  ArrowLeft, Bell, MessageSquare, Paperclip, ClipboardCheck, Download, Unlink, Link2, Settings2, FileText,
} from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'
import ErrorPanel from '../components/ErrorPanel.jsx'
import { SEVERITIES, STATUSES, DemoBadge, SeverityBadge, StatusBadge } from '../components/Badges.jsx'
import { apiFetch, apiUrl } from '../api/client.js'
import { useApi } from '../hooks/useApi.js'
import { useAuth } from '../auth/AuthContext.jsx'
import { INCIDENT_TRANSITIONS, NEEDS_RESOLUTION } from '../config/workflow.js'
import { formatBytes, formatDate, SOURCE_LABELS } from '../utils/format.js'

const statusLabel = (id) => STATUSES.find((s) => s.id === id)?.label ?? id

export default function IncidentDetailPage() {
  const { id } = useParams()
  const { hasRole } = useAuth()
  const canEdit = hasRole('analyst')
  const { data: inc, error, loading, reload } = useApi(`/incidents/${id}`)
  const { data: assignable } = useApi(canEdit ? '/users/assignable' : null)
  const { data: unlinked, reload: reloadUnlinked } = useApi(canEdit ? '/alerts?unlinked=true&limit=50' : null)

  const [actionError, setActionError] = useState(null)
  const [note, setNote] = useState('')
  const [writeup, setWriteup] = useState(null) // {resolution, recommendations} while editing
  const [evidenceDesc, setEvidenceDesc] = useState('')
  const [evidenceFile, setEvidenceFile] = useState(null)
  const [linkIds, setLinkIds] = useState(new Set())
  const [busy, setBusy] = useState(false)

  async function run(fn) {
    setActionError(null)
    setBusy(true)
    try {
      await fn()
      reload()
      reloadUnlinked()
    } catch (err) {
      setActionError(err)
    } finally {
      setBusy(false)
    }
  }

  const patch = (body) => run(() => apiFetch(`/incidents/${id}`, { method: 'PATCH', body }))

  if (error) return <ErrorPanel error={error} onRetry={reload} />
  if (loading && !inc) return <p className="text-sm text-soc-muted">Loading…</p>
  if (!inc) return null

  const editing = writeup ?? { resolution: inc.resolution ?? '', recommendations: inc.recommendations ?? '' }
  const hasResolution = (inc.resolution ?? '').trim().length > 0

  const alertColumns = [
    { key: 'severity', label: 'Severity', render: (a) => <SeverityBadge severity={a.severity} /> },
    { key: 'title', label: 'Alert', render: (a) => <Link className="hover:text-soc-accent" to={`/alerts/${a.id}`}>{a.title} {a.is_simulated && <DemoBadge />}</Link> },
    { key: 'src_ip', label: 'Source IP', render: (a) => <code className="font-mono text-xs">{a.src_ip ?? '—'}</code> },
    { key: 'source', label: 'Detected by', render: (a) => SOURCE_LABELS[a.source] },
    { key: 'detected_at', label: 'Detected at', render: (a) => formatDate(a.detected_at) },
    ...(canEdit ? [{
      key: 'unlink', label: '',
      render: (a) => (
        <button type="button" className="text-soc-muted hover:text-rose-300" title="Unlink alert" aria-label={`Unlink alert ${a.id}`}
          onClick={() => run(() => apiFetch(`/incidents/${id}/alerts/${a.id}`, { method: 'DELETE' }))}>
          <Unlink className="h-4 w-4" />
        </button>
      ),
    }] : []),
  ]

  return (
    <>
      <Link to="/incidents" className="mb-4 inline-flex items-center gap-1 text-sm text-soc-muted hover:text-soc-text">
        <ArrowLeft className="h-4 w-4" aria-hidden="true" /> All incidents
      </Link>
      <PageHeader
        title={`Incident #${inc.id}: ${inc.title}`}
        description={inc.description}
        actions={
          <a className="btn-secondary" href={apiUrl(`/reports/incidents/${inc.id}.pdf`)}>
            <FileText className="h-4 w-4" aria-hidden="true" /> PDF report
          </a>
        }
      />
      <div className="mb-6 flex flex-wrap items-center gap-2 text-sm">
        <SeverityBadge severity={inc.severity} />
        <StatusBadge status={inc.status} />
        {inc.is_simulated && <DemoBadge />}
        <span className="text-soc-muted">
          Opened {formatDate(inc.created_at)}{inc.created_by && ` by ${inc.created_by}`}
          {inc.closed_at && ` · closed ${formatDate(inc.closed_at)}`}
        </span>
      </div>
      {actionError && <ErrorPanel error={actionError} />}

      {canEdit && (
        <Card title="Workflow" icon={Settings2} className="mb-6">
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <p className="label">Move to</p>
              <div className="flex flex-wrap gap-2">
                {INCIDENT_TRANSITIONS[inc.status].map((next) => {
                  const blocked = NEEDS_RESOLUTION.includes(next) && !hasResolution
                  return (
                    <button key={next} type="button" className="btn-secondary" disabled={busy || blocked}
                      title={blocked ? 'Save a resolution first' : undefined} onClick={() => patch({ status: next })}>
                      {statusLabel(next)}
                    </button>
                  )
                })}
              </div>
              {!hasResolution && (
                <p className="mt-2 text-xs text-soc-muted">Resolving or closing requires a written resolution (below).</p>
              )}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label htmlFor="sev" className="label">Severity</label>
                <select id="sev" className="input" value={inc.severity} onChange={(e) => patch({ severity: e.target.value })}>
                  {SEVERITIES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
                </select>
              </div>
              <div>
                <label htmlFor="assignee" className="label">Assignee</label>
                <select id="assignee" className="input" value={inc.assignee_id ?? ''}
                  onChange={(e) => patch({ assignee_id: e.target.value ? Number(e.target.value) : null })}>
                  <option value="">Unassigned</option>
                  {(assignable ?? []).map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
                </select>
              </div>
            </div>
          </div>
        </Card>
      )}

      <Card title={`Linked alerts (${inc.alerts.length})`} icon={Bell}>
        <DataTable caption="Linked alerts" columns={alertColumns} rows={inc.alerts}
          empty={<EmptyState icon={Bell} title="No alerts linked" />} />
        {canEdit && (unlinked?.items?.length ?? 0) > 0 && (
          <details className="mt-4 rounded-lg border border-soc-border bg-soc-bg p-3">
            <summary className="cursor-pointer text-sm font-medium">
              <Link2 className="mr-1 inline h-4 w-4" aria-hidden="true" /> Link more alerts
            </summary>
            <ul className="mt-3 max-h-60 space-y-1 overflow-y-auto text-sm">
              {unlinked.items.map((a) => (
                <li key={a.id}>
                  <label className="flex items-center gap-2">
                    <input type="checkbox" checked={linkIds.has(a.id)} onChange={() => {
                      const next = new Set(linkIds)
                      next.has(a.id) ? next.delete(a.id) : next.add(a.id)
                      setLinkIds(next)
                    }} />
                    <SeverityBadge severity={a.severity} /> #{a.id} {a.title} {a.is_simulated && <DemoBadge />}
                  </label>
                </li>
              ))}
            </ul>
            <button type="button" className="btn-primary mt-3" disabled={busy || linkIds.size === 0}
              onClick={() => run(async () => {
                await apiFetch(`/incidents/${id}/alerts`, { method: 'POST', body: { alert_ids: [...linkIds] } })
                setLinkIds(new Set())
              })}>
              Link {linkIds.size} alert(s)
            </button>
          </details>
        )}
      </Card>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card title="Investigation notes" icon={MessageSquare}>
          {inc.notes.length === 0 ? (
            <EmptyState icon={MessageSquare} title="No notes yet" />
          ) : (
            <ol className="space-y-3">
              {inc.notes.map((n) => (
                <li key={n.id} className="rounded-lg border border-soc-border bg-soc-bg p-3">
                  <p className="text-xs text-soc-muted">{n.author ?? 'deleted user'} · {formatDate(n.created_at)}</p>
                  <p className="mt-1 whitespace-pre-wrap text-sm">{n.body}</p>
                </li>
              ))}
            </ol>
          )}
          {canEdit && (
            <form className="mt-4" onSubmit={(e) => {
              e.preventDefault()
              run(async () => {
                await apiFetch(`/incidents/${id}/notes`, { method: 'POST', body: { body: note } })
                setNote('')
              })
            }}>
              <label htmlFor="note" className="label">Add note</label>
              <textarea id="note" rows={3} className="input" maxLength={10000} value={note} onChange={(e) => setNote(e.target.value)}
                placeholder="What did you check? What did you find?" />
              <button type="submit" className="btn-primary mt-2" disabled={busy || !note.trim()}>Add note</button>
              <p className="mt-1 text-xs text-soc-muted">Notes are permanent (they can't be edited or deleted) to keep an honest record.</p>
            </form>
          )}
        </Card>

        <Card title="Evidence" icon={Paperclip}>
          {inc.evidence.length === 0 ? (
            <EmptyState icon={Paperclip} title="No evidence recorded" />
          ) : (
            <ul className="space-y-3">
              {inc.evidence.map((ev) => (
                <li key={ev.id} className="rounded-lg border border-soc-border bg-soc-bg p-3 text-sm">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="font-medium">{ev.original_name ?? 'Note-only evidence'}</p>
                      {ev.description && <p className="text-soc-muted">{ev.description}</p>}
                    </div>
                    {ev.has_file && canEdit && (
                      <a className="btn-secondary shrink-0 px-2 py-1 text-xs" href={apiUrl(`/evidence/${ev.id}/download`)}>
                        <Download className="h-3.5 w-3.5" aria-hidden="true" /> Download
                      </a>
                    )}
                  </div>
                  {ev.sha256 && (
                    <p className="mt-2 break-all font-mono text-[11px] text-soc-muted" title="SHA-256 fingerprint at upload time">
                      SHA-256 {ev.sha256}
                    </p>
                  )}
                  <p className="mt-1 text-xs text-soc-muted">
                    {ev.size_bytes != null && `${formatBytes(ev.size_bytes)} · `}{ev.uploaded_by} · {formatDate(ev.created_at)}
                  </p>
                </li>
              ))}
            </ul>
          )}
          {canEdit && (
            <form className="mt-4 space-y-2" onSubmit={(e) => {
              e.preventDefault()
              const form = new FormData()
              if (evidenceFile) form.append('file', evidenceFile)
              if (evidenceDesc.trim()) form.append('description', evidenceDesc)
              run(async () => {
                await apiFetch(`/incidents/${id}/evidence`, { method: 'POST', body: form })
                setEvidenceDesc('')
                setEvidenceFile(null)
                e.target.reset()
              })
            }}>
              <label htmlFor="ev-file" className="label">Add evidence</label>
              <input id="ev-file" type="file" className="input file:mr-3 file:rounded file:border-0 file:bg-soc-raised file:px-2 file:py-1 file:text-soc-text"
                accept=".log,.txt,.json,.jsonl,.csv,.pcap,.pcapng,.png,.jpg,.jpeg,.pdf"
                onChange={(e) => setEvidenceFile(e.target.files[0] ?? null)} />
              <input className="input" placeholder="Description (e.g. where it was collected)" aria-label="Evidence description"
                maxLength={5000} value={evidenceDesc} onChange={(e) => setEvidenceDesc(e.target.value)} />
              <button type="submit" className="btn-primary" disabled={busy || (!evidenceFile && !evidenceDesc.trim())}>Save evidence</button>
              <p className="text-xs text-soc-muted">Max 20 MB · logs, text, pcap, PNG/JPEG, PDF. A SHA-256 hash is recorded at upload.</p>
            </form>
          )}
        </Card>
      </div>

      <Card title="Resolution & recommendations" icon={ClipboardCheck} className="mt-6">
        {canEdit ? (
          <form className="grid gap-4 lg:grid-cols-2" onSubmit={(e) => {
            e.preventDefault()
            run(async () => {
              await apiFetch(`/incidents/${id}`, { method: 'PATCH', body: editing })
              setWriteup(null)
            })
          }}>
            <div>
              <label htmlFor="resolution" className="label">Resolution (root cause, actions taken)</label>
              <textarea id="resolution" rows={6} className="input" maxLength={10000} value={editing.resolution}
                onChange={(e) => setWriteup({ ...editing, resolution: e.target.value })} />
            </div>
            <div>
              <label htmlFor="recommendations" className="label">Recommendations (prevent recurrence)</label>
              <textarea id="recommendations" rows={6} className="input" maxLength={10000} value={editing.recommendations}
                onChange={(e) => setWriteup({ ...editing, recommendations: e.target.value })} />
            </div>
            <div className="lg:col-span-2">
              <button type="submit" className="btn-primary" disabled={busy || writeup === null}>Save write-up</button>
            </div>
          </form>
        ) : (
          <dl className="grid gap-4 lg:grid-cols-2 text-sm">
            <div><dt className="label">Resolution</dt><dd className="whitespace-pre-wrap">{inc.resolution || '—'}</dd></div>
            <div><dt className="label">Recommendations</dt><dd className="whitespace-pre-wrap">{inc.recommendations || '—'}</dd></div>
          </dl>
        )}
      </Card>
    </>
  )
}
