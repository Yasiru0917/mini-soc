// Previous/next pager for list endpoints that return {items, total}.
import { ChevronLeft, ChevronRight } from 'lucide-react'

export default function Pagination({ total, limit, offset, onChange }) {
  if (!total) return null
  const from = offset + 1
  const to = Math.min(offset + limit, total)
  return (
    <div className="mt-4 flex items-center justify-between gap-3 text-xs text-soc-muted">
      <span>
        {from}–{to} of {total}
      </span>
      <div className="flex gap-2">
        <button type="button" className="btn-secondary px-2 py-1" disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))} aria-label="Previous page">
          <ChevronLeft className="h-4 w-4" />
        </button>
        <button type="button" className="btn-secondary px-2 py-1" disabled={to >= total}
          onClick={() => onChange(offset + limit)} aria-label="Next page">
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}
