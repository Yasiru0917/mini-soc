// Incident Management - investigations built from one or more alerts.
//
// Alert vs incident: an alert is a signal; an incident is a confirmed (or
// suspected) security problem that someone is responsible for investigating,
// with notes, evidence and a documented resolution.
import { Briefcase, GitBranch, ClipboardList, ChevronRight } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import PlaceholderNotice from '../components/PlaceholderNotice.jsx'
import Card from '../components/Card.jsx'
import DataTable from '../components/DataTable.jsx'
import EmptyState from '../components/EmptyState.jsx'

const COLUMNS = [
  { key: 'id', label: 'ID' },
  { key: 'title', label: 'Title' },
  { key: 'severity', label: 'Severity' },
  { key: 'status', label: 'Status' },
  { key: 'assignee', label: 'Assignee' },
  { key: 'alerts', label: 'Linked alerts' },
  { key: 'updated', label: 'Last updated' },
]

// Main path of the incident lifecycle (based on the NIST incident response cycle).
const LIFECYCLE = ['New', 'Investigating', 'Contained', 'Resolved', 'Closed']

// What each incident record will hold.
const RECORD_PARTS = [
  { name: 'Investigation notes', about: 'Timestamped notes written by analysts.' },
  { name: 'Evidence', about: 'Files and artefacts, stored with a SHA-256 hash to prove they were not altered.' },
  { name: 'Resolution', about: 'Root cause and the actions taken to contain and fix the issue.' },
  { name: 'Recommendations', about: 'What to change so it does not happen again.' },
]

export default function IncidentsPage() {
  return (
    <>
      <PageHeader
        title="Incident Management"
        description="Escalate alerts into incidents, record investigation notes and evidence, and document the resolution."
        actions={
          <button type="button" className="btn-primary" disabled title="Available in Phase 4">
            New incident
          </button>
        }
      />

      <PlaceholderNotice phase={4}>
        Incidents cannot be created yet. In Phase 4 you will be able to create an incident
        directly from one or more alerts.
      </PlaceholderNotice>

      <Card title="Incidents" icon={Briefcase}>
        <DataTable
          caption="Incidents"
          columns={COLUMNS}
          empty={<EmptyState icon={Briefcase} title="No incidents" />}
        />
      </Card>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card title="Investigation lifecycle" icon={GitBranch}>
          <ol className="flex flex-wrap items-center gap-2 text-sm">
            {LIFECYCLE.map((step, i) => (
              <li key={step} className="flex items-center gap-2">
                <span className="rounded-md border border-soc-border bg-soc-bg px-2.5 py-1">{step}</span>
                {i < LIFECYCLE.length - 1 && <ChevronRight className="h-4 w-4 text-soc-muted" aria-hidden="true" />}
              </li>
            ))}
          </ol>
          <p className="mt-3 text-xs text-soc-muted">
            At any stage an incident can instead be closed as a <em>false positive</em>, with a
            written justification.
          </p>
        </Card>

        <Card title="What an incident record contains" icon={ClipboardList}>
          <dl className="space-y-3 text-sm">
            {RECORD_PARTS.map((p) => (
              <div key={p.name}>
                <dt className="font-medium">{p.name}</dt>
                <dd className="text-xs text-soc-muted">{p.about}</dd>
              </div>
            ))}
          </dl>
        </Card>
      </div>
    </>
  )
}
