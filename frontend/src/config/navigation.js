// Single source of truth for the sidebar menu.
// The sidebar, the top bar title and the page headers all read from here,
// so adding a module later means adding ONE entry to this list.
//
// `phase` is the development phase in which the module's backend arrives.
// The UI uses it to label placeholders honestly ("Planned - Phase 4").
import {
  LayoutDashboard,
  Network,
  Bell,
  Briefcase,
  ScrollText,
  Globe,
  FileText,
  Settings,
} from 'lucide-react'

export const NAV_GROUPS = [
  {
    label: 'Core operations',
    items: [
      { to: '/', label: 'Dashboard', icon: LayoutDashboard, phase: 3 },
      { to: '/network', label: 'Network Scanning', icon: Network, phase: 5 },
      { to: '/alerts', label: 'Alerts', icon: Bell, phase: 4 },
      { to: '/incidents', label: 'Incidents', icon: Briefcase, phase: 4 },
      { to: '/logs', label: 'Log Analysis', icon: ScrollText, phase: 6 },
    ],
  },
  {
    label: 'Intelligence & reporting',
    items: [
      { to: '/threat-intel', label: 'Threat Intel', icon: Globe, phase: 8 },
      { to: '/reports', label: 'Reports', icon: FileText, phase: 8 },
    ],
  },
  {
    label: 'System',
    items: [{ to: '/settings', label: 'Settings', icon: Settings, phase: 3 }],
  },
]

// Flat list, handy for looking up the current page by URL.
export const NAV_ITEMS = NAV_GROUPS.flatMap((group) => group.items)

export function findNavItem(pathname) {
  return NAV_ITEMS.find((item) => item.to === pathname)
}
