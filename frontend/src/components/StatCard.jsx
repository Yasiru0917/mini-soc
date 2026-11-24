// A single metric tile (e.g. "Critical alerts: 3").
//
// If `value` is null/undefined we show an em dash and "No data source",
// NOT the number 0. "0" is a claim ("we looked and found nothing");
// "-" means "we have not looked". That difference is important in security.
export default function StatCard({ label, value, accentClass = 'bg-soc-accent', hint }) {
  const hasValue = value !== null && value !== undefined

  return (
    <div className="card relative overflow-hidden p-4">
      {/* Coloured strip on the left identifies the metric's category */}
      <span className={`absolute inset-y-0 left-0 w-1 ${accentClass}`} aria-hidden="true" />
      <p className="text-xs font-medium uppercase tracking-wider text-soc-muted">{label}</p>
      <p className="mt-2 font-mono text-3xl font-semibold">{hasValue ? value : '—'}</p>
      <p className="mt-1 text-xs text-soc-muted">{hasValue ? hint : hint ?? 'No data source yet'}</p>
    </div>
  )
}
