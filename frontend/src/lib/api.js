// Authenticated API helpers for pages that fetch their own data.

const authHeaders = () => {
  const token = localStorage.getItem('fhm_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

const handle = async (res) => {
  if (res.status === 401) {
    localStorage.removeItem('fhm_token')
    window.dispatchEvent(new Event('fhm:logout'))
    throw new Error('Unauthorized')
  }
  if (!res.ok) {
    const data = await res.json().catch(() => null)
    throw new Error(data?.detail || `Request failed (${res.status})`)
  }
  return res.json()
}

export const apiGet = (path) => fetch(path, { headers: authHeaders() }).then(handle)

export const apiPost = (path, body) =>
  fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body ?? {}),
  }).then(handle)

export const apiDelete = (path) => fetch(path, { method: 'DELETE', headers: authHeaders() }).then(handle)
