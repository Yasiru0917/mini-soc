// The "shell" around every page: sidebar on the left, top bar above,
// and the current page rendered in <Outlet /> (React Router fills it in).
//
// Responsive behaviour:
//  - Large screens (lg = 1024px+): sidebar is always visible.
//  - Smaller screens: sidebar is hidden and slides in as a drawer when the
//    menu button is pressed. It closes on navigation, on the Escape key,
//    or when the dark overlay is clicked.
import { useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar.jsx'
import Topbar from './Topbar.jsx'

export default function AppLayout() {
  const [drawerOpen, setDrawerOpen] = useState(false)
  const { pathname } = useLocation()

  // Close the mobile drawer whenever the route changes.
  useEffect(() => {
    setDrawerOpen(false)
  }, [pathname])

  // Close the drawer with the Escape key (keyboard accessibility).
  useEffect(() => {
    if (!drawerOpen) return
    const onKey = (e) => e.key === 'Escape' && setDrawerOpen(false)
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [drawerOpen])

  return (
    <div className="min-h-screen lg:pl-64">
      {/* Desktop sidebar (fixed). */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 lg:block">
        <Sidebar />
      </aside>

      {/* Mobile drawer + overlay. */}
      {drawerOpen && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <div className="absolute inset-0 bg-black/60" onClick={() => setDrawerOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-72 max-w-[85%] shadow-2xl">
            <Sidebar onClose={() => setDrawerOpen(false)} />
          </aside>
        </div>
      )}

      <Topbar onMenuClick={() => setDrawerOpen(true)} />

      <main className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        <Outlet />
      </main>
    </div>
  )
}
