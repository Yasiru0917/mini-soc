// Load data from a GET endpoint and track loading / error state.
//
//   const { data, error, loading, reload } = useApi('/dashboard/summary')
//
// If the component unmounts (user navigates away) before the response
// arrives, the request is aborted so we never update a page that's gone.
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.js'

export function useApi(path) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [version, setVersion] = useState(0)

  useEffect(() => {
    // Pass a null path to skip loading (e.g. the user lacks the needed role).
    if (!path) {
      setLoading(false)
      return undefined
    }
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    apiFetch(path, { signal: controller.signal })
      .then(setData)
      .catch((err) => {
        if (err.name !== 'AbortError') setError(err)
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => controller.abort()
  }, [path, version])

  const reload = useCallback(() => setVersion((v) => v + 1), [])
  return { data, error, loading, reload }
}
