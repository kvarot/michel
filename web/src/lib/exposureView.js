// Pure functions behind the exposure part of a server's sheet: what the last
// check saw listen, from inside the server, in three columns. Nothing here says
// that a service can be reached, or cannot: the firewall of the host is never
// read. No DOM, no fetch. Vitest covers them (exposureView.test.js).
import { translate } from '../i18n/index.js'
import { localDay, validateDecision } from './digestView.js'

/**
 * The lines GET /targets/{id}/exposure always ends with, as the Go catalogs
 * write them: the page has its own two rows for these. A test reads the Go
 * catalogs, so a wording that drifts fails there, not on the page.
 */
const alwaysLines = new Set(["Le pare-feu de l'hébergeur", 'The firewall of the host', 'Les services en UDP', 'Services in UDP'])

const namedServices = ['web', 'admin', 'database', 'cache']

const isReserved = (scope) => scope === 'server' || scope === 'private'

/** serviceKey is the name of a service in the catalogs; an unknown one is « other ». */
const serviceKey = (service) => (namedServices.includes(service) ? service : 'other')

/** sentence ends a reason written by the person, so that what follows reads as another sentence. */
function sentence(text) {
  const s = String(text || '').trim()
  return /[.!?…]$/.test(s) ? s : `${s}.`
}

/**
 * @typedef {{name: string, note: string, tag: 'close'|'normal'|'check'|null, findingId: string, detail: string, decided: boolean}} Row
 */

/**
 * exposureColumns makes the three columns. Not read is never an empty list that
 * looks clean: the handler sends no service then, and the columns say « not
 * read ». A read with no service at all does not exist (Michel has just come in
 * through one), so it counts as not read too. A word « to close » is only for a
 * service open to all, on a server where Michel opens findings: on a shared
 * server it may be the host's or another client's (R8). A reason given keeps
 * the service in its column (R12).
 * @param {object|null} view GET /targets/{id}/exposure
 * @param {object|null} target the TargetView, whose kind is the fresher one after a change
 * @param {string} lang
 * @param {boolean} advanced numbers and addresses are for the advanced mode
 * @returns {{read: boolean, title: string, sub: string, shared: string, checked: string, open: Row[], reserved: Row[], unverified: Row[], empty: {open: string, reserved: string}, closed: {name: string, text: string, when: string, detail: string}[]}}
 */
export function exposureColumns(view, target, lang, advanced) {
  const t = (key, params) => translate(lang, key, params)
  const services = Array.isArray(view?.services) ? view.services.filter(Boolean) : []
  const read = !!view?.read && services.length > 0
  const shared = (target?.kind || view?.kind) === 'shared'
  const server = target?.name || ''

  const row = (s) => {
    const key = serviceKey(s.service)
    const found = !!s.finding_id
    const out = {
      name: t(`expo.service.${key}`),
      note: '',
      tag: null,
      findingId: s.finding_id || '',
      detail: advanced ? `${s.port} · ${(s.addresses || []).join(', ')}` : '',
      decided: false,
    }
    if (isReserved(s.scope)) {
      out.note = t(`expo.reserved.${s.scope}`)
      return out
    }
    if (s.decided_why) {
      out.note = t('expo.decided', { why: sentence(s.decided_why) })
      out.decided = true
      return out
    }
    const close = s.verdict === 'close'
    if (close && !shared) {
      out.tag = 'close'
      out.note = t(`expo.service.${key}_note`)
    } else if (found) {
      // A finding outlives what opened it: a server that became shared, or a port that became the connection one.
      out.tag = 'check'
      out.note = t('expo.kept')
    } else if (close) {
      out.tag = 'check'
      out.note = t('expo.shared_note')
    } else if (s.verdict === 'normal') {
      out.tag = 'normal'
      out.note = t(`expo.service.${key}_note`)
    } else {
      out.tag = 'check'
      out.note = t('expo.service.other_note')
    }
    return out
  }

  const shown = read ? services : []
  const open = shown.filter((s) => !isReserved(s.scope)).map(row)
  const reserved = shown.filter((s) => isReserved(s.scope)).map(row)
  const unverified = [
    { name: t('expo.firewall.name'), note: t('expo.firewall.note'), tag: null, findingId: '', detail: '', decided: false },
    { name: t('expo.udp.name'), note: t('expo.udp.note'), tag: null, findingId: '', detail: '', decided: false },
    ...(view?.unseen || [])
      .filter((u) => u && !alwaysLines.has(u.what))
      .map((u) => ({ name: u.what, note: u.reason, tag: null, findingId: '', detail: '', decided: false })),
  ]

  let title = t('expo.title.not_read', { server })
  if (read && !open.length) title = t('expo.title.none', { server })
  if (read && open.length) {
    const toClose = open.filter((r) => r.tag === 'close').length
    title = t('expo.title', { server, n: open.length }) + (toClose ? t('expo.title.of_close', { n: toClose }) : '')
  }

  const none = t(read ? 'expo.col.none' : 'expo.col.not_read')
  const closed = (view?.closed || []).filter(Boolean).map((c) => {
    const name = t(`expo.service.${serviceKey(c.service)}`)
    const day = localDay(c.last_seen_open, lang)
    return {
      name,
      // Not read now: the last complete read said so, and that is all Michel knows.
      text: t(read ? 'expo.closed' : 'expo.closed_unread', { service: name }),
      when: day ? t('expo.closed_date', { date: day }) : '',
      detail: advanced ? String(c.port) : '',
    }
  })

  const day = read ? localDay(view.checked_at, lang) : ''
  return {
    read,
    title,
    sub: t('expo.sub'),
    shared: shared ? t('expo.shared') : '',
    checked: day ? t('expo.checked', { date: day }) : '',
    open,
    reserved,
    unverified,
    empty: { open: none, reserved: none },
    closed,
  }
}

/**
 * exposureFindingIds are the findings the columns show, with their path and
 * their decision: the sheet's list of flaws does not say them a second time. A
 * finding of a list not read has no row, and stays in that list.
 * @param {object|null} view GET /targets/{id}/exposure
 * @returns {Set<string>}
 */
export function exposureFindingIds(view) {
  const list = view?.read && Array.isArray(view.services) ? view.services : []
  return new Set(list.filter((s) => s && s.finding_id && !isReserved(s.scope)).map((s) => s.finding_id))
}

/**
 * exposureDecisionCheck is the check of « Je sais, c'est bloqué ou voulu »: an
 * ignore, so a reason is required (R12), under the rules of every decision.
 * @param {string} why
 * @param {Date} now
 * @returns {{ok: boolean, errorKey: string}}
 */
export function exposureDecisionCheck(why, now) {
  return validateDecision({ action: 'ignore', why, until: '' }, now)
}

/**
 * closedExposures are the lines of the Resolved page: what a server read now no
 * longer shows open to all. A server not read now says nothing of what is open,
 * so it gives no line.
 * @param {object[]|null} servers GET /targets
 * @param {Object<string, object>|null} views a server's id to GET /targets/{id}/exposure
 * @returns {{server: {id: string, name: string}, service: string, at: string}[]}
 */
export function closedExposures(servers, views) {
  const out = []
  for (const s of servers || []) {
    const v = views?.[s?.id]
    if (!v?.read) continue
    for (const c of v.closed || []) {
      if (c) out.push({ server: { id: s.id, name: s.name }, service: c.service, at: c.last_seen_open })
    }
  }
  return out
}
