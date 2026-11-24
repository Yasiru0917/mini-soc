// Authentication state shared by the whole app (React "context").
//
// Because the session cookie is HttpOnly, JavaScript cannot read it to find
// out who is logged in. Instead, on startup we ask the server: GET /auth/me.
//  - 200 -> we get the user (username + role)
//  - 401 -> nobody is signed in
//
// Role checks here (hasRole) only decide what to SHOW. The server enforces
// the real permissions on every request.
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { apiFetch, ApiError } from '../api/client.js'

const AuthContext = createContext(null)

const ROLE_LEVEL = { viewer: 1, analyst: 2, admin: 3 }

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  // 'checking' until the first /auth/me answer, then 'ready'.
  const [status, setStatus] = useState('checking')
  const [startupError, setStartupError] = useState(null)

  const refresh = useCallback(async () => {
    try {
      setUser(await apiFetch('/auth/me'))
      setStartupError(null)
    } catch (err) {
      setUser(null)
      // 401 just means "not signed in". Anything else (API down) is shown to the user.
      if (!(err instanceof ApiError && err.status === 401)) setStartupError(err)
    } finally {
      setStatus('ready')
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  // Session expired or revoked while using the app -> forget the user.
  useEffect(() => {
    const onExpired = () => setUser(null)
    window.addEventListener('auth:expired', onExpired)
    return () => window.removeEventListener('auth:expired', onExpired)
  }, [])

  const login = useCallback(async (username, password) => {
    const loggedIn = await apiFetch('/auth/login', { method: 'POST', body: { username, password } })
    setUser(loggedIn)
    setStartupError(null)
    return loggedIn
  }, [])

  const logout = useCallback(async () => {
    try {
      await apiFetch('/auth/logout', { method: 'POST' })
    } finally {
      setUser(null) // clear locally even if the server call failed
    }
  }, [])

  const hasRole = useCallback(
    (minimum) => !!user && ROLE_LEVEL[user.role] >= ROLE_LEVEL[minimum],
    [user],
  )

  const value = useMemo(
    () => ({ user, status, startupError, login, logout, refresh, hasRole }),
    [user, status, startupError, login, logout, refresh, hasRole],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
