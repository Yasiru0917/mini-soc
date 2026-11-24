// Generic panel with an optional title row.
export default function Card({ title, icon: Icon, actions, className = '', children }) {
  return (
    // min-w-0: inside CSS grids, let the card shrink so wide tables scroll
    // inside it instead of stretching the whole page on phones.
    <section className={`card min-w-0 ${className}`}>
      {(title || actions) && (
        <div className="flex items-center justify-between gap-3 border-b border-soc-border px-5 py-3">
          <h2 className="card-title flex items-center gap-2">
            {Icon && <Icon className="h-4 w-4 text-soc-accent" aria-hidden="true" />}
            {title}
          </h2>
          {actions}
        </div>
      )}
      <div className="p-5">{children}</div>
    </section>
  )
}
