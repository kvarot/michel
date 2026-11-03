// Pure functions behind the navigation: which page an address shows, which
// entry is lit, and whether the menu sits on the side or at the bottom. No
// DOM, no storage. Vitest covers them (navView.test.js).
import { fixRoute } from './fixView.js'
import { serversRoute } from './serversView.js'

/**
 * The five entries of the menu, in order. Icons are SVG paths (24x24)
 * written here: nothing is downloaded.
 * @type {{page: string, hash: string, key: string, shortKey: string, icon: string}[]}
 */
export const navEntries = [
  { page: 'todo', hash: '#/', key: 'nav.todo', shortKey: 'nav.short.todo', icon: 'M9 16.2 4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4z' },
  { page: 'projects', hash: '#/projects', key: 'nav.projects', shortKey: 'nav.short.projects', icon: 'M10 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-8z' },
  { page: 'servers', hash: '#/servers', key: 'nav.servers', shortKey: 'nav.short.servers', icon: 'M4 4h16a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zm0 9h16a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-5a1 1 0 0 1 1-1zM6 7v2h2V7zm0 9v2h2v-2z' },
  { page: 'resolved', hash: '#/resolved', key: 'nav.resolved', shortKey: 'nav.short.resolved', icon: 'M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5zm-1.2 14.4-3.6-3.6 1.4-1.4 2.2 2.2 4.6-4.6 1.4 1.4z' },
  { page: 'settings', hash: '#/settings', key: 'nav.settings', shortKey: 'nav.short.settings', icon: 'M19.4 13a7.5 7.5 0 0 0 0-2l2.1-1.6-2-3.5-2.5 1a7.4 7.4 0 0 0-1.7-1L15 3.2h-4l-.4 2.7a7.4 7.4 0 0 0-1.7 1l-2.5-1-2 3.5L6.6 11a7.5 7.5 0 0 0 0 2l-2.1 1.6 2 3.5 2.5-1a7.4 7.4 0 0 0 1.7 1l.4 2.7h4l.4-2.7a7.4 7.4 0 0 0 1.7-1l2.5 1 2-3.5zM13 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7z' },
]

/**
 * pageOf reads the page from the address hash. An unknown address shows
 * the To-do page.
 * @param {string} hash
 * @returns {'todo'|'projects'|'servers'|'resolved'|'settings'|'sources'|'fix'}
 */
export function pageOf(hash) {
  const h = String(hash || '')
  if (h === '#/projects') return 'projects'
  if (h === '#/resolved') return 'resolved'
  if (h === '#/settings') return 'settings'
  if (h === '#/sources') return 'sources'
  if (serversRoute(h)) return 'servers'
  if (fixRoute(h)) return 'fix'
  return 'todo'
}

/**
 * activeEntry is the menu entry to light for a page: a fix belongs to
 * To do, the sources to Settings.
 * @param {string} page
 */
export function activeEntry(page) {
  if (page === 'fix') return 'todo'
  if (page === 'sources') return 'settings'
  return page
}

/**
 * navMode: the menu stands on the side from 960 px, at the bottom below.
 * @param {number} width window width in px
 * @returns {'side'|'bottom'}
 */
export function navMode(width) {
  return Number(width) >= 960 ? 'side' : 'bottom'
}
