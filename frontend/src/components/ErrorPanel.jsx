// Shows an API error plainly, with a retry button. Errors are never hidden.
import { TriangleAlert, RotateCw } from 'lucide-react'

export default function ErrorPanel({ error, onRetry }) {
  return (
    <div role="alert" className="mb-6 flex flex-col gap-3 rounded-xl border border-sev-critical/40 bg-sev-critical/10 p-4 text-sm sm:flex-row sm:items-center">
      <TriangleAlert className="h-5 w-5 shrink-0 text-sev-critical" aria-hidden="true" />
      <div className="flex-1">
        <p className="font-semibold text-rose-200">Could not load data</p>
        <p className="text-soc-muted">{error?.message ?? 'Unknown error'}</p>
      </div>
      {onRetry && (
        <button type="button" onClick={onRetry} className="btn-secondary">
          <RotateCw className="h-4 w-4" aria-hidden="true" /> Retry
        </button>
      )}
    </div>
  )
}
