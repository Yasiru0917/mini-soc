// Threat Intelligence - check whether an IP/domain/hash is known to be bad.
//
// Reputation data is an OPINION from a third party, not proof. That is why
// each result will show WHO said it, WHEN, and HOW CONFIDENT they are.
import { Globe, Search, Database } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import PlaceholderNotice from '../components/PlaceholderNotice.jsx'
import Card from '../components/Card.jsx'
import { PlannedBadge } from '../components/Badges.jsx'

const PROVIDERS = [
  { name: 'AbuseIPDB', checks: 'IP addresses', reliability: 'Community reports with a 0–100 confidence score' },
  { name: 'VirusTotal', checks: 'IPs, domains, file hashes', reliability: 'Aggregates verdicts from many security vendors' },
  { name: 'AlienVault OTX', checks: 'IPs, domains, hashes', reliability: 'Community threat "pulses", quality varies' },
]

export default function ThreatIntelPage() {
  return (
    <>
      <PageHeader
        title="Threat Intelligence"
        description="Investigate suspicious indicators using external reputation services."
      />

      <PlaceholderNotice phase={8}>
        No reputation providers are connected. API keys will be read from the server's
        environment and never stored in the browser.
      </PlaceholderNotice>

      <Card title="Indicator lookup" icon={Search}>
        <form className="flex flex-col gap-3 sm:flex-row" onSubmit={(e) => e.preventDefault()}>
          <label htmlFor="ioc" className="sr-only">Indicator</label>
          <input id="ioc" className="input font-mono" placeholder="IP address, domain or SHA-256 hash" disabled />
          <button type="submit" className="btn-primary sm:w-40" disabled title="Available in Phase 8">
            <Search className="h-4 w-4" aria-hidden="true" /> Look up
          </button>
        </form>
        <p className="mt-3 text-xs text-soc-muted">
          Private lab addresses (such as 192.168.56.x) have no public reputation and will not be
          sent to external services.
        </p>
      </Card>

      <Card title="Reputation providers" icon={Database} className="mt-6">
        <ul className="divide-y divide-soc-border">
          {PROVIDERS.map((p) => (
            <li key={p.name} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="flex items-center gap-2 text-sm font-medium">
                  <Globe className="h-4 w-4 text-soc-muted" aria-hidden="true" /> {p.name}
                </p>
                <p className="text-xs text-soc-muted">Checks: {p.checks} · {p.reliability}</p>
              </div>
              <PlannedBadge phase={8} />
            </li>
          ))}
        </ul>
      </Card>
    </>
  )
}
