// Small coloured labels used across the app.
// Keeping them in one file guarantees "critical" looks identical everywhere.

// Severity levels, highest first. `description` is shown in the legend so
// analysts share one definition of each level.
export const SEVERITIES = [
  { id: 'critical', label: 'Critical', dot: 'bg-sev-critical', text: 'text-sev-critical',
    description: 'Active compromise or imminent risk. Respond immediately.' },
  { id: 'high', label: 'High', dot: 'bg-sev-high', text: 'text-sev-high',
    description: 'Likely malicious activity that needs investigation today.' },
  { id: 'medium', label: 'Medium', dot: 'bg-sev-medium', text: 'text-sev-medium',
    description: 'Suspicious activity worth reviewing (e.g. repeated failed logins).' },
  { id: 'low', label: 'Low', dot: 'bg-sev-low', text: 'text-sev-low',
    description: 'Unusual but probably benign; useful context.' },
  { id: 'info', label: 'Info', dot: 'bg-sev-info', text: 'text-sev-info',
    description: 'Informational event, no action required.' },
]

export function SeverityBadge({ severity }) {
  const s = SEVERITIES.find((x) => x.id === severity) ?? SEVERITIES.at(-1)
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full bg-soc-raised px-2.5 py-0.5 text-xs font-semibold ${s.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} aria-hidden="true" />
      {s.label}
    </span>
  )
}

// Alert workflow states.
export const ALERT_STATUSES = [
  { id: 'new', label: 'New' },
  { id: 'investigating', label: 'Investigating' },
  { id: 'resolved', label: 'Resolved' },
  { id: 'false_positive', label: 'False positive' },
  { id: 'closed', label: 'Closed' },
]

// Incident workflow states (incidents also have "contained").
export const STATUSES = [
  { id: 'new', label: 'New' },
  { id: 'investigating', label: 'Investigating' },
  { id: 'contained', label: 'Contained' },
  { id: 'resolved', label: 'Resolved' },
  { id: 'false_positive', label: 'False positive' },
  { id: 'closed', label: 'Closed' },
]

export function StatusBadge({ status }) {
  const s = STATUSES.find((x) => x.id === status)
  return (
    <span className="inline-flex rounded-md border border-soc-border px-2 py-0.5 text-xs text-soc-text">
      {s?.label ?? status}
    </span>
  )
}

// Marks SIMULATED data. Any record created by the demo seed script will
// carry this badge, so it can never be mistaken for a real detection.
export function DemoBadge() {
  return (
    <span
      className="inline-flex rounded-md border border-demo/40 bg-demo/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-demo"
      title="Simulated demonstration data - not a real detection"
    >
      Demo
    </span>
  )
}

// "Planned" label for features listed in the UI but not yet built.
export function PlannedBadge({ phase }) {
  return (
    <span className="inline-flex whitespace-nowrap rounded-md border border-amber-500/30 px-2 py-0.5 text-[11px] text-amber-300">
      Planned · Phase {phase}
    </span>
  )
}
