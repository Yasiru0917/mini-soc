// Threat Intelligence - check whether an IP / domain / file hash is known to be bad.
//
// Reputation data is a third party's OPINION, not proof. Each result shows
// WHO said it, WHEN, their own score and what it means, and how reliable that
// kind of source is. Private/internal indicators are never sent outside.
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Search, Database, History, ExternalLink, Info } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'
import { apiFetch } from '../api/client.js'
import { useApi } from '../hooks/useApi.js'
import { useAuth } from '../auth/AuthContext.jsx'
import { formatDate } from '../utils/format.js'

const VERDICT_STYLE = {
  malicious: 'border-sev-critical/50 bg-sev-critical/10 text-rose-200',
  suspicious: 'border-sev-medium/50 bg-sev-medium/10 text-amber-200',
  harmless: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200',
  unknown: 'border-soc-border bg-soc-raised text-soc-muted',
}
const STATUS_TEXT = {
  not_configured: 'Not configured (no API key)',
  unsupported: 'Does not support this indicator type',
  error: 'Error',
}

function Verdict({ verdict }) {
  return (
    <span className={`inline-flex rounded-md border px-2 py-0.5 text-xs font-semibold uppercase tracking-wider ${VERDICT_STYLE[verdict] ?? VERDICT_STYLE.unknown}`}>
      {verdict ?? 'n/a'}
    </span>
  )
}

function ProviderCard({ r }) {
  const facts = Object.entries(r.summary ?? {}).filter(([, v]) => v !== null && v !== undefined && v !== '')
  return (
    <section className="card p-4">
      <div className="flex items-start justify-between gap-2">
        <h3 className="font-semibold">{r.provider}</h3>
        {r.status === 'ok' ? <Verdict verdict={r.verdict} /> : <span className="text-xs text-soc-muted">{STATUS_TEXT[r.status] ?? r.status}</span>}
      </div>
      {r.status === 'ok' && (
        <>
          <p className="mt-2 text-sm">{r.score_label}</p>
          {facts.length > 0 && (
            <dl className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
              {facts.map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-soc-muted">{k}</dt>
                  <dd className="break-words">{String(v)}</dd>
                </div>
              ))}
            </dl>
          )}
          <p className="mt-3 text-[11px] text-soc-muted">
            Queried {formatDate(r.queried_at)}{r.cached && ' (cached)'}
            {r.reference_url && (
              <> · <a className="inline-flex items-center gap-0.5 text-soc-accent" href={r.reference_url} target="_blank" rel="noopener noreferrer">
                View on {r.provider} <ExternalLink className="h-3 w-3" aria-hidden="true" /></a></>
            )}
          </p>
        </>
      )}
      {r.error && <p className="mt-2 text-xs text-rose-300">{r.error}</p>}
      <p className="mt-3 flex gap-1.5 border-t border-soc-border pt-2 text-[11px] text-soc-muted">
        <Info className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" /> {r.reliability_note}
      </p>
    </section>
  )
}

export default function ThreatIntelPage() {
  const { hasRole } = useAuth()
  const [params] = useSearchParams()
  const [indicator, setIndicator] = useState(params.get('q') ?? '')
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const history = useApi('/threat-intel/history')
  const { data: integrations } = useApi('/integrations/status')

  async function lookup(e, force = false) {
    e?.preventDefault()
    setBusy(true)
    setError(null)
    try {
      setResult(await apiFetch('/threat-intel/lookup', { method: 'POST', body: { indicator, force_refresh: force } }))
      history.reload()
    } catch (err) {
      setError(err.message)
      setResult(null)
    } finally {
      setBusy(false)
    }
  }

  const intelProviders = (integrations ?? []).filter((i) => ['AbuseIPDB', 'VirusTotal', 'AlienVault OTX'].includes(i.name))
  const historyColumns = [
    { key: 'indicator', label: 'Indicator', render: (h) => <code className="font-mono text-xs">{h.indicator}</code> },
    { key: 'type', label: 'Type' },
    { key: 'provider', label: 'Provider' },
    { key: 'verdict', label: 'Verdict', render: (h) => <Verdict verdict={h.verdict} /> },
    { key: 'queried_by', label: 'By' },
    { key: 'queried_at', label: 'When', render: (h) => formatDate(h.queried_at) },
  ]

  return (
    <>
      <PageHeader title="Threat Intelligence" description="Investigate suspicious indicators using external reputation services." />

      <Card title="Indicator lookup" icon={Search}>
        {hasRole('analyst') ? (
          <form className="flex flex-col gap-3 sm:flex-row" onSubmit={lookup}>
            <label htmlFor="ioc" className="sr-only">Indicator</label>
            <input id="ioc" className="input font-mono" placeholder="Public IP, domain, or MD5/SHA-1/SHA-256 hash" maxLength={255}
              value={indicator} onChange={(e) => setIndicator(e.target.value)} />
            <button type="submit" className="btn-primary sm:w-40" disabled={busy || !indicator.trim()}>
              <Search className="h-4 w-4" aria-hidden="true" /> {busy ? 'Looking up…' : 'Look up'}
            </button>
          </form>
        ) : (
          <p className="text-sm text-soc-muted">Lookups send data to external services, so they are limited to analysts and admins.</p>
        )}
        {error && <p role="alert" className="mt-3 text-sm text-rose-300">{error}</p>}
        <p className="mt-3 text-xs text-soc-muted">
          Private lab addresses (e.g. 192.168.56.x) and internal domain names are refused: they have no public reputation and sending them would leak network details.
        </p>
      </Card>

      {result && (
        <section className="mt-6" aria-label="Lookup results">
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <h2 className="font-mono text-lg">{result.indicator}</h2>
            <span className="text-xs uppercase tracking-wider text-soc-muted">{result.type}</span>
            {result.overall_verdict && <span className="text-sm">Overall: <Verdict verdict={result.overall_verdict} /></span>}
            <button type="button" className="btn-secondary ml-auto px-3 py-1 text-xs" onClick={() => lookup(null, true)} disabled={busy}>
              Refresh (ignore cache)
            </button>
          </div>
          <p className="mb-4 text-xs text-soc-muted">{result.note}</p>
          <div className="grid gap-4 lg:grid-cols-3">
            {result.results.map((r) => <ProviderCard key={r.provider} r={r} />)}
          </div>
        </section>
      )}

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card title="Providers" icon={Database}>
          <ul className="space-y-2 text-sm">
            {intelProviders.map((p) => (
              <li key={p.name} className="flex items-center justify-between gap-2">
                <span>{p.name}</span>
                <span className="inline-flex items-center gap-1.5 text-xs text-soc-muted">
                  <span className={`h-2 w-2 rounded-full ${p.state === 'available' ? 'bg-emerald-400' : 'bg-soc-muted'}`} aria-hidden="true" />
                  {p.state === 'available' ? 'API key set' : 'Not configured'}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-soc-muted">Add free API keys to <code className="font-mono">backend/.env</code> and restart the backend.</p>
        </Card>
        <Card title="Recent lookups" icon={History} className="lg:col-span-2">
          <DataTable caption="Recent lookups" columns={historyColumns} rowKey="key"
            rows={(history.data ?? []).map((h, i) => ({ ...h, key: `${h.indicator}-${h.provider}-${i}` }))}
            empty={<EmptyState icon={History} title="No lookups yet" />} />
        </Card>
      </div>
    </>
  )
}
