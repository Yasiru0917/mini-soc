// Display-only configuration for the frontend.
//
// IMPORTANT (security): nothing here is a security control. Anything the
// browser holds can be changed by the user with DevTools. The real
// authorized scan scope will be stored and ENFORCED by the backend
// (Phase 5). The frontend only shows it so analysts know the rules.

// Default authorized scanning scope: the VirtualBox host-only network.
// Only machines in this lab network are ours to scan.
export const DEFAULT_SCAN_SCOPE = '192.168.56.0/24'

// Development status, shown in the top bar.
export const CURRENT_PHASE = 2
