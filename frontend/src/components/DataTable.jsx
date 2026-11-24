// Reusable table.
//
// columns: [{ key: 'ip', label: 'IP address', render?: (row) => JSX }]
// rows:    array of objects (empty for now - real rows arrive from the API)
// empty:   what to show when there are no rows
//
// On narrow screens the table scrolls sideways INSIDE its card, so the
// page itself never scrolls horizontally.
import EmptyState from './EmptyState.jsx'

export default function DataTable({ columns, rows = [], empty, caption, rowKey = 'id' }) {
  const isEmpty = rows.length === 0

  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-left text-sm">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr className="border-b border-soc-border text-xs uppercase tracking-wider text-soc-muted">
            {columns.map((col) => (
              <th key={col.key} scope="col" className="whitespace-nowrap px-4 py-3 font-medium">
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
          {!isEmpty && (
            <tbody>
              {rows.map((row) => (
                <tr key={row[rowKey]} className="border-b border-soc-border/60 hover:bg-soc-raised/50">
                  {columns.map((col) => (
                    <td key={col.key} className="whitespace-nowrap px-4 py-3">
                      {col.render ? col.render(row) : row[col.key]}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          )}
        </table>
      </div>
      {/* The empty message sits OUTSIDE the scrolling area so it stays
          centred and readable on phones (the table itself is 640px+ wide). */}
      {isEmpty && (empty ?? <EmptyState title="No records" />)}
    </>
  )
}
