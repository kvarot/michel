// Pure functions behind the Sources page: no DOM, no fetch, no storage.
// Vitest covers them (sourcesView.test.js). t is a translate function bound
// to the page's language: t(key, params) returns the text.

/** Kinds of sources, in the order the page shows them. */
export const kinds = ['osv', 'enrichment', 'feed', 'plugin', 'skill', 'mcp', 'reference']

const states = ['on', 'waiting_consent', 'off', 'hidden']
const badges = ['new_version', 'suggested', 'archived']

/**
 * groupByKind puts the sources in one group per kind, in the fixed order of
 * kinds; a kind without source is left out, an unknown kind is dropped.
 * @param {{kind: string}[]} sources
 * @returns {{kind: string, sources: object[]}[]}
 */
export function groupByKind(sources) {
  const list = Array.isArray(sources) ? sources : []
  return kinds
    .map((kind) => ({ kind, sources: list.filter((s) => s.kind === kind) }))
    .filter((g) => g.sources.length)
}

/** @param {string} state @returns {string} the i18n key of a displayed state; off for an unknown one. */
export function stateLabelKey(state) {
  return `sources.state.${states.includes(state) ? state : 'off'}`
}

/** @param {{badges?: string[]}} source @returns {string[]} the i18n keys of its known badges, in order. */
export function badgeKeys(source) {
  const own = source?.badges || []
  return badges.filter((b) => own.includes(b)).map((b) => `sources.badge.${b}`)
}

/**
 * consentSentence is the sentence of the consent dialog for one host: the
 * server's text (already in the page's language), else one naming the host.
 * @param {{host: string, what?: string}} consent
 */
export function consentSentence(consent, t) {
  if (!consent) return ''
  return consent.what || t('consent.contact', { host: consent.host })
}

/**
 * agoText says how long ago an RFC 3339 time was: just now, minutes, hours,
 * then days. "" for no time.
 */
export function agoText(iso, now, t) {
  const at = new Date(String(iso || ''))
  if (!iso || Number.isNaN(at.getTime())) return ''
  const minutes = Math.floor((now.getTime() - at.getTime()) / 60000)
  if (minutes < 1) return t('ago.now')
  if (minutes < 60) return t('ago.minutes', { n: minutes })
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return t('ago.hours', { n: hours })
  return t('ago.days', { n: Math.floor(hours / 24) })
}

/**
 * lastReadText is the line under a source: when it was last read and what
 * came of it ("2 h ago · 14 new items", or the error in plain words).
 * @param {{at: string, result: string, error?: string, items?: number}} last
 */
export function lastReadText(last, now, t) {
  if (!last || !last.at) return t('sources.last.never')
  const ago = agoText(last.at, now, t)
  switch (last.result) {
    case 'ok':
      return t('sources.last.ok', { ago, n: last.items || 0 })
    case 'error':
      return t('sources.last.error', { ago, error: last.error || '?' })
    case 'waiting_consent':
    case 'skipped':
    case 'denied':
    case 'unreachable':
      return t(`sources.last.${last.result}`, { ago })
    default:
      return ago
  }
}

/**
 * summary counts the sources on and those waiting for consent, and finds
 * the latest successful read (RFC 3339, "" if none), for the page's header.
 * @returns {{on: number, waiting: number, lastAt: string}}
 */
export function summary(sources) {
  const out = { on: 0, waiting: 0, lastAt: '' }
  for (const s of sources || []) {
    if (s.state === 'on') out.on += 1
    if (s.state === 'waiting_consent') out.waiting += 1
    const at = s.last_read?.result === 'ok' ? s.last_read.at : ''
    if (at && (!out.lastAt || new Date(at) > new Date(out.lastAt))) out.lastAt = at
  }
  return out
}
