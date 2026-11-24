// Shown for any URL that doesn't match a route.
import { Link } from 'react-router-dom'
import { SearchX } from 'lucide-react'

export default function NotFoundPage() {
  return (
    <div className="flex flex-col items-center py-20 text-center">
      <SearchX className="h-10 w-10 text-soc-muted" aria-hidden="true" />
      <h1 className="mt-4 text-2xl font-bold">Page not found</h1>
      <p className="mt-2 text-sm text-soc-muted">The page you requested does not exist.</p>
      <Link to="/" className="btn-primary mt-6">Go to dashboard</Link>
    </div>
  )
}
