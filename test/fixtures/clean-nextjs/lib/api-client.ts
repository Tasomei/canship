// Test fixture: `withCredentials` and `credentials: 'include'` are *client*
// settings. They say what this code sends, not what the server accepts, and
// reading them as server policy would flag the public wildcard below.
import axios from 'axios'

export const api = axios.create({ baseURL: '/api', withCredentials: true })

/** Sent on our genuinely public endpoints. Correct, and not paired with anything. */
export const PUBLIC_CORS = { 'Access-Control-Allow-Origin': '*' }

export function loadMe(): Promise<Response> {
  return fetch('/api/me', { credentials: 'include' })
}
