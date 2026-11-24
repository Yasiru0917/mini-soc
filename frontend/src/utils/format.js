// Small display helpers shared by many pages.

export function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  let value = bytes
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i += 1
  }
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

// Human labels for the `source` provenance field.
export const SOURCE_LABELS = {
  nmap: 'Nmap scan',
  log_rule: 'Log rule',
  pcap: 'Packet capture',
  wazuh: 'Wazuh',
  threat_intel: 'Threat intel',
  manual: 'Analyst',
  demo: 'Demo',
}
