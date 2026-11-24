// Shown where a list or chart has nothing to display.
import { Inbox } from 'lucide-react'

export default function EmptyState({ icon: Icon = Inbox, title, children }) {
  return (
    <div className="flex flex-col items-center justify-center px-4 py-10 text-center">
      <Icon className="h-8 w-8 text-soc-muted/60" aria-hidden="true" />
      <p className="mt-3 text-sm font-medium">{title}</p>
      {children && <p className="mt-1 max-w-md text-xs text-soc-muted">{children}</p>}
    </div>
  )
}
