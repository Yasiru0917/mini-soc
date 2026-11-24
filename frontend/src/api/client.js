// Small wrapper around fetch() used for every API call.
//
// - Always sends cookies for our own origin (credentials: 'same-origin'),
//   which is how the HttpOnly session cookie reaches the server.
//   JavaScript never sees or stores the token itself.
// - Turns HTTP errors into ApiError objects with a readable message,
//   so pages can show real errors instead of failing silently.
// - On 401 it broadcasts 'auth:expired' so the app can send the user to
//   the login page when their session times out.

const API_BASE = '/api/v1'

export class ApiError extends Error {
  constructor(status, message, details) {
    super(message)
    this.status = status
    this.details = details
  }
}

// FastAPI errors look like {detail: "text"} or, for validation (422),
// {detail: [{loc: [...], msg: "..."}]}. Convert both to one readable string.
function messageFrom(body, status) {
  const detail = body?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail.map((d) => `${d.loc?.at(-1) ?? 'field'}: ${d.msg}`).join('; ')
  }
  if (status === 429) return 'Too many attempts. Please wait and try again.'
  if (status >= 500) return 'Server error. Check the backend console.'
  return `Request failed (HTTP ${status})`
}

export async function apiFetch(path, { method = 'GET', body, signal } = {}) {
  let response
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      credentials: 'same-origin',
      headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
    })
  } catch (err) {
    if (err.name === 'AbortError') throw err
    // fetch only throws on network failure (backend not running, proxy down).
    throw new ApiError(0, 'Cannot reach the API. Is the backend running on port 8000?')
  }

  if (response.status === 204) return null

  const isJson = response.headers.get('content-type')?.includes('application/json')
  const data = isJson ? await response.json() : null

  if (!response.ok) {
    // Login failures are 401 too, but they are not an "expired session".
    if (response.status === 401 && path !== '/auth/login') {
      window.dispatchEvent(new Event('auth:expired'))
    }
    throw new ApiError(response.status, messageFrom(data, response.status), data)
  }
  return data
}
