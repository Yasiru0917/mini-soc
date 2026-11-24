// Route table: maps each URL to a page component.
//
// All main pages are nested inside <AppLayout>, which draws the sidebar and
// top bar once and renders the current page in its <Outlet />.
// The login page sits outside the layout because it has no sidebar.
//
// Phase 3 will wrap the nested routes in an auth guard so that only
// signed-in users can reach them (and the backend will enforce roles).
import { Routes, Route } from 'react-router-dom'
import AppLayout from './layouts/AppLayout.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import NetworkPage from './pages/NetworkPage.jsx'
import AlertsPage from './pages/AlertsPage.jsx'
import IncidentsPage from './pages/IncidentsPage.jsx'
import LogsPage from './pages/LogsPage.jsx'
import ThreatIntelPage from './pages/ThreatIntelPage.jsx'
import ReportsPage from './pages/ReportsPage.jsx'
import SettingsPage from './pages/SettingsPage.jsx'
import LoginPage from './pages/LoginPage.jsx'
import NotFoundPage from './pages/NotFoundPage.jsx'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<AppLayout />}>
        <Route index element={<DashboardPage />} />
        <Route path="network" element={<NetworkPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="logs" element={<LogsPage />} />
        <Route path="threat-intel" element={<ThreatIntelPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
