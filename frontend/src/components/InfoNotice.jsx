// Neutral information banner (as opposed to PlaceholderNotice, which marks
// unbuilt features). Used to explain what live data does and doesn't cover.
import { Info } from 'lucide-react'

export default function InfoNotice({ title, children }) {
  return (
    <div role="note" className="mb-6 flex gap-3 rounded-xl border border-soc-accent/25 bg-soc-accent/5 p-4 text-sm">
      <Info className="mt-0.5 h-5 w-5 shrink-0 text-soc-accent" aria-hidden="true" />
      <div>
        {title && <p className="font-semibold text-soc-accent">{title}</p>}
        <div className="mt-1 text-soc-muted">{children}</div>
      </div>
    </div>
  )
}
