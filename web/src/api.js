// The page's only door to Michel: fetch on /api/v1 with the local token in
// "Authorization: Bearer". A 401 fires the "unauthorized" event so the page
// can ask for the token; a failed connection is an ApiError with offline set.
import { reactive } from 'vue'
import { keys, load, save } from './lib/storage.js'

const base = '/api/v1'

/**
 * ApiError carries the server's {error, hint}, or offline when it could not
 * be reached; data is the whole answer (a 409 for consent lists the hosts).
 */
export class ApiError extends Error {
  constructor({ status = 0, error = '', hint = '', offline = false, data = null }) {
    super(error || `HTTP ${status}`)
    this.status = status
    this.error = error
    this.hint = hint
    this.offline = offline
    this.data = data
  }
}

const events = new EventTarget()

async function request(method, path, body) {
  const headers = { Accept: 'application/json' }
  if (api.token) headers.Authorization = `Bearer ${api.token}`
  const init = { method, headers, cache: 'no-store', credentials: 'omit' }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  let resp
  try {
    resp = await fetch(base + path, init)
  } catch {
    throw new ApiError({ offline: true })
  }
  let data = null
  try {
    data = await resp.json()
  } catch {
    data = null
  }
  if (resp.status === 401) events.dispatchEvent(new Event('unauthorized'))
  if (!resp.ok) {
    throw new ApiError({ status: resp.status, error: data?.error || '', hint: data?.hint || '', data })
  }
  return data
}

// state is reactive so components showing whether a token is saved follow it.
const state = reactive({ token: load(keys.token) })

export const api = {
  get token() {
    return state.token
  },
  /** setToken keeps t for the next requests and in this browser ("" forgets it). */
  setToken(t) {
    state.token = String(t || '').trim()
    save(keys.token, state.token)
  },
  get(path) {
    return request('GET', path)
  },
  post(path, body) {
    return request('POST', path, body)
  },
  /** del sends DELETE, with a JSON body when one is given. */
  del(path, body) {
    return request('DELETE', path, body)
  },
  /** on listens to "unauthorized"; it returns the function that stops listening. */
  on(name, fn) {
    events.addEventListener(name, fn)
    return () => events.removeEventListener(name, fn)
  },
}

/**
 * takeTokenFromURL moves ?token= from the address bar into the api (and this
 * browser's storage), then removes it from the address and the history entry.
 */
export function takeTokenFromURL() {
  const url = new URL(window.location.href)
  const t = url.searchParams.get('token')
  if (t === null) return
  api.setToken(t)
  url.searchParams.delete('token')
  window.history.replaceState(window.history.state, '', url.pathname + url.search + url.hash)
}
