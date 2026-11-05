// Pure functions behind the navigation: which page an address shows, which
// entry is lit, and whether the menu sits on the side or at the bottom. No
// DOM, no storage. Vitest covers them (navView.test.js).
import { fixRoute } from './fixView.js'
import { serversRoute } from './serversView.js'

/**
 * The entries of the menu, in order, with their group: « Suivi » (follow),
 * « Parc » (park), then the settings. bottom says the entry stays in the
 * bottom bar below 960 px (five at most: the resolved problems are reached
 * from the overview there). Icons are SVG paths (24x24) written here:
 * nothing is downloaded.
 * @type {{page: string, hash: string, key: string, shortKey: string, group: string, bottom: boolean, icon: string}[]}
 */
export const navEntries = [
  { page: 'todo', hash: '#/', key: 'nav.todo', shortKey: 'nav.short.todo', group: 'follow', bottom: true, icon: 'M3 13h8V3H3zm0 8h8v-6H3zm10 0h8V11h-8zm0-18v6h8V3z' },
  { page: 'findings', hash: '#/findings', key: 'nav.findings', shortKey: 'nav.short.findings', group: 'follow', bottom: true, icon: 'M12 2 1 21h22zm1 16h-2v-2h2zm0-4h-2v-4h2z' },
  { page: 'resolved', hash: '#/resolved', key: 'nav.resolved', shortKey: 'nav.short.resolved', group: 'follow', bottom: false, icon: 'M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5zm-1.2 14.4-3.6-3.6 1.4-1.4 2.2 2.2 4.6-4.6 1.4 1.4z' },
  { page: 'projects', hash: '#/projects', key: 'nav.projects', shortKey: 'nav.short.projects', group: 'park', bottom: true, icon: 'M10 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-8z' },
  { page: 'servers', hash: '#/servers', key: 'nav.servers', shortKey: 'nav.short.servers', group: 'park', bottom: true, icon: 'M4 4h16a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zm0 9h16a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-5a1 1 0 0 1 1-1zM6 7v2h2V7zm0 9v2h2v-2z' },
  { page: 'settings', hash: '#/settings', key: 'nav.settings', shortKey: 'nav.short.settings', group: 'other', bottom: true, icon: 'M19.4 13a7.5 7.5 0 0 0 0-2l2.1-1.6-2-3.5-2.5 1a7.4 7.4 0 0 0-1.7-1L15 3.2h-4l-.4 2.7a7.4 7.4 0 0 0-1.7 1l-2.5-1-2 3.5L6.6 11a7.5 7.5 0 0 0 0 2l-2.1 1.6 2 3.5 2.5-1a7.4 7.4 0 0 0 1.7 1l.4 2.7h4l.4-2.7a7.4 7.4 0 0 0 1.7-1l2.5 1 2-3.5zM13 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7z' },
]

/** The groups of the side menu, in order. */
export const navGroups = ['follow', 'park', 'other']

/**
 * entriesFor is the menu of a mode: every entry on the side, grouped
 * ({group, entries}), the bottom ones at the bottom (one group, '').
 * @param {'side'|'bottom'} mode
 * @returns {{group: string, entries: object[]}[]}
 */
export function entriesFor(mode) {
  if (mode === 'bottom') return [{ group: '', entries: navEntries.filter((e) => e.bottom) }]
  return navGroups.map((group) => ({ group, entries: navEntries.filter((e) => e.group === group) }))
}

/**
 * pageOf reads the page from the address hash. An unknown address shows
 * the overview (page 'todo').
 * @param {string} hash
 * @returns {'todo'|'findings'|'projects'|'servers'|'resolved'|'settings'|'sources'|'fix'}
 */
export function pageOf(hash) {
  const h = String(hash || '')
  if (h === '#/projects') return 'projects'
  if (h === '#/resolved') return 'resolved'
  if (h === '#/settings') return 'settings'
  if (h === '#/sources') return 'sources'
  if (/^#\/findings(?:\?[^#]*)?$/.test(h)) return 'findings'
  if (serversRoute(h)) return 'servers'
  if (fixRoute(h)) return 'fix'
  return 'todo'
}

/**
 * activeEntry is the menu entry to light for a page: a flaw's page belongs
 * to the findings, the sources to Settings. At the bottom, where the
 * resolved problems have no entry, they belong to the overview.
 * @param {string} page
 * @param {'side'|'bottom'} [mode]
 */
export function activeEntry(page, mode = 'side') {
  if (page === 'fix') return 'findings'
  if (page === 'sources') return 'settings'
  if (page === 'resolved' && mode === 'bottom') return 'todo'
  return page
}

/**
 * openBadge is the number the « Failles » entry shows: the open findings the
 * digest counts in every project (deferred included, ignored left out, as
 * the digest counts them). null when the digest or a count cannot be read:
 * the entry then shows no number rather than a wrong one.
 * @param {object|null} digest GET /today
 * @returns {number|null}
 */
export function openBadge(digest) {
  if (!digest || !Array.isArray(digest.projects)) return null
  let n = 0
  for (const p of digest.projects) {
    if (!p || !p.open || typeof p.open !== 'object') return null
    for (const v of Object.values(p.open)) {
      if (!Number.isInteger(v) || v < 0) return null
      n += v
    }
  }
  return n
}

/**
 * navMode: the menu stands on the side from 960 px, at the bottom below.
 * @param {number} width window width in px
 * @returns {'side'|'bottom'}
 */
export function navMode(width) {
  return Number(width) >= 960 ? 'side' : 'bottom'
}
