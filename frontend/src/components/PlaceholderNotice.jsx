// A clearly-labelled banner for functionality that is NOT built yet.
//
// Why this matters: a security tool must never look like it is working when
// it is not. An empty dashboard that silently shows "0 alerts" could make an
// analyst believe the network is clean. This banner says plainly that the
// feature does not exist yet, and when it is planned.
import { Construction } from 'lucide-react'

export default function PlaceholderNotice({ phase, children }) {
  return (
    <div
      role="note"
      className="mb-6 flex gap-3 rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 text-sm"
    >
      <Construction className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" aria-hidden="true" />
      <div>
        <p className="font-semibold text-amber-300">
          Not implemented yet{phase ? ` · planned for Phase ${phase}` : ''}
        </p>
        <div className="mt-1 text-soc-muted">{children}</div>
      </div>
    </div>
  )
}
