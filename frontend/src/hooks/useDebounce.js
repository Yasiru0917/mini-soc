// Delay a fast-changing value (e.g. a search box) so we don't send an API
// request on every keystroke.
import { useEffect, useState } from 'react'

export function useDebounce(value, delayMs = 300) {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(timer)
  }, [value, delayMs])
  return debounced
}
