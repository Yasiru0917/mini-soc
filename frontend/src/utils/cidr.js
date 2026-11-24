// Tiny IPv4 helpers for an instant "in scope?" hint in the scan form.
// This is only a convenience: the server performs the real check.

function ipToInt(ip) {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part) || Number(part) > 255) return null
    n = n * 256 + Number(part)
  }
  return n
}

export function parseCidr(text) {
  const [ip, bitsText = '32'] = text.trim().split('/')
  const base = ipToInt(ip)
  const bits = Number(bitsText)
  if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null
  const size = 2 ** (32 - bits)
  const start = Math.floor(base / size) * size
  return { start, end: start + size - 1, bits }
}

// 'in' | 'out' | 'invalid' (IPv6 targets return 'invalid' here; the server handles them)
export function scopeCheck(target, scopeCidrs) {
  const t = parseCidr(target)
  if (!t) return 'invalid'
  const inside = scopeCidrs.some((c) => {
    const s = parseCidr(c)
    return s && t.start >= s.start && t.end <= s.end
  })
  return inside ? 'in' : 'out'
}
