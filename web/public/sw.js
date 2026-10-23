// Michel's service worker, written by hand. It keeps only the page's shell
// (the page and its built files) so the page opens without michel serve and
// says how to start it. It never stores an answer of the API: /api/ always
// goes to the network, and fails there when michel serve is not running.
//
// - install, and each page load from the network: precache the files listed
//   in sw-manifest.json (made by the build) if that build is not cached yet,
//   and drop the caches of older builds;
// - fetch: /api/ untouched (network only); the page itself network first,
//   the cached copy when offline; every other file cache first (their names
//   carry a hash, so a cached copy is never stale).

const PREFIX = 'michel-shell-'

async function readManifest() {
  const resp = await fetch('/sw-manifest.json', { cache: 'no-store' })
  if (!resp.ok) throw new Error(`sw-manifest.json: ${resp.status}`)
  return resp.json()
}

/**
 * refreshShell precaches the current build when it is not cached yet, then
 * drops the older ones. sw.js itself does not change between builds, so this
 * runs at install and again each time the page loads from the network.
 */
async function refreshShell() {
  const manifest = await readManifest()
  const keep = PREFIX + manifest.version
  if (!(await caches.has(keep))) {
    const cache = await caches.open(keep)
    try {
      // cache: reload skips the HTTP cache, so the copy is the served one.
      await cache.addAll(manifest.files.map((f) => new Request(f, { cache: 'reload' })))
    } catch (err) {
      await caches.delete(keep)
      throw err
    }
  }
  for (const name of await caches.keys()) {
    if (name.startsWith(PREFIX) && name !== keep) await caches.delete(name)
  }
}

self.addEventListener('install', (event) => {
  event.waitUntil(refreshShell().then(() => self.skipWaiting()))
})

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim())
})

/** isPage tells whether the request is the page itself ("/" with or without a query). */
function isPage(request, url) {
  return request.mode === 'navigate' || url.pathname === '/'
}

async function pageNetworkFirst(event, request) {
  try {
    const resp = await fetch(request)
    // michel serve answers: a newer build may be there, cache it for offline.
    event.waitUntil(refreshShell().catch(() => {}))
    return resp
  } catch (err) {
    const cached = await caches.match('/', { ignoreSearch: true })
    if (cached) return cached
    throw err
  }
}

async function cacheFirst(request) {
  const cached = await caches.match(request)
  if (cached) return cached
  return fetch(request)
}

self.addEventListener('fetch', (event) => {
  const { request } = event
  if (request.method !== 'GET') return
  const url = new URL(request.url)
  if (url.origin !== self.location.origin) return
  // The API is never cached: let the browser go to the network.
  if (url.pathname.startsWith('/api/')) return
  if (url.pathname === '/sw.js' || url.pathname === '/sw-manifest.json') return
  event.respondWith(isPage(request, url) ? pageNetworkFirst(event, request) : cacheFirst(request))
})
