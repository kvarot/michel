// Pure functions behind the exposure part of a server's sheet: what the last
// check saw listen, from inside the server, in three columns. Nothing here says
// that a service can be reached, or cannot: the firewall of the host is never
// read. No DOM, no fetch. Vitest covers them (exposureView.test.js).
import { translate } from '../i18n/index.js'
import { localDay, validateDecision } from './digestView.js'

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
 * name, note and detail are always on screen, so in simple mode they hold no
 * number: port and the lines of advice are for « Que faire ? » and the dialog,
 * which explain it in their own sentence. advice is empty when there is nothing
 * to do; undo says how to change your mind on a decided row.
 * @typedef {{name: string, note: string, tag: 'close'|'normal'|'check'|null, findingId: string, port: number, detail: string, decided: boolean, advice: string[], undo: string}} Row
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
 * @param {boolean} [failed] the page could not get the view: Michel may well have read it
 * @returns {{read: boolean, failed: boolean, title: string, sub: string, shared: string, checked: string, open: Row[], reserved: Row[], unverified: Row[], empty: {open: string, reserved: string}, closed: {name: string, text: string, when: string, detail: string}[]}}
 */
export function exposureColumns(view, target, lang, advanced, failed = false) {
  const t = (key, params) => translate(lang, key, params)
  const services = Array.isArray(view?.services) ? view.services.filter(Boolean) : []
  const read = !!view?.read && services.length > 0
  const shared = (target?.kind || view?.kind) === 'shared'
  const server = target?.name || ''
  // The administration numbers Michel reads (a number shown in two scopes is one). When there is
  // only one, not the number Michel connects by, and no other service he cannot name, the connection
  // probably ends there through a redirection (a mapped port, a router): an inference, said as one.
  // With several, or with an unknown listener that could be the real one, he cannot tell.
  const adminPorts = new Set(services.filter((s) => serviceKey(s.service) === 'admin' && s.verdict === 'normal').map((s) => s.port))
  const unknownListener = services.some((s) => s.verdict === 'unknown')
  const mappedAdmin = adminPorts.size === 1 && !!target?.port && !adminPorts.has(target.port) && !unknownListener

  // adviceOf: a flaw has the whole advice, a service to close too even before
  // its flaw exists; a service only to check has one line.
  const adviceOf = (out) => {
    if (out.findingId || out.tag === 'close') {
      const lines = [t('plan.exposure'), t('expo.how'), t('expo.ask', { number: out.port })]
      return out.findingId ? lines : [...lines, t('expo.how_no_finding')]
    }
    return out.tag === 'check' ? [t('expo.check_how', { number: out.port })] : []
  }

  const row = (s) => {
    const key = serviceKey(s.service)
    const found = !!s.finding_id
    const out = {
      name: t(`expo.service.${key}`),
      note: '',
      tag: null,
      findingId: s.finding_id || '',
      port: s.port,
      detail: advanced ? `${s.port} · ${(s.addresses || []).join(', ')}` : '',
      decided: false,
      advice: [],
      undo: '',
    }
    if (isReserved(s.scope)) {
      out.note = t(`expo.reserved.${s.scope}`)
      return out
    }
    if (s.decided_why) {
      out.note = t('expo.decided', { why: sentence(s.decided_why) })
      out.decided = true
      if (found) out.undo = t('expo.decided_undo', { id: s.finding_id })
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
    } else if (s.verdict === 'normal' && key === 'admin' && mappedAdmin) {
      out.tag = 'normal'
      out.note = t('expo.service.admin_mapped_note', { number: target.port })
    } else if (s.verdict === 'normal' && key === 'admin' && target?.port && s.port !== target.port) {
      // The usual administration number, and not the one Michel comes in by.
      out.tag = 'check'
      out.note = t('expo.service.admin_other_note')
    } else if (s.verdict === 'normal') {
      out.tag = 'normal'
      out.note = t(`expo.service.${key}_note`)
    } else {
      out.tag = 'check'
      out.note = t('expo.service.other_note')
    }
    out.advice = adviceOf(out)
    return out
  }

  const shown = read ? services : []
  const open = shown.filter((s) => !isReserved(s.scope)).map(row)
  const reserved = shown.filter((s) => isReserved(s.scope)).map(row)
  const plain = (name, note) => ({ name, note, tag: null, findingId: '', port: 0, detail: '', decided: false, advice: [], undo: '' })
  const unverified = [
    plain(t('expo.firewall.name'), t('expo.firewall.note')),
    plain(t('expo.udp.name'), t('expo.udp.note')),
    // A line with a key is one of the two above, which the page words itself.
    ...(view?.unseen || []).filter((u) => u && !u.key).map((u) => plain(u.what, u.reason)),
  ]

  let title = t(failed ? 'expo.title.load_failed' : 'expo.title.not_read', { server })
  if (read && !open.length) title = t('expo.title.none', { server })
  if (read && open.length) {
    const toClose = open.filter((r) => r.tag === 'close').length
    title = t('expo.title', { server, n: open.length }) + (toClose ? t('expo.title.of_close', { n: toClose }) : '')
  }

  const none = failed ? '' : t(read ? 'expo.col.none' : 'expo.col.not_read')
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
    failed,
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
 * exposureDecisionTarget is what the dialog needs to decide a flaw from its card
 * in the list of flaws, when the columns have no row for it because the list was
 * not read. The route takes it: without this, a server that no longer reads would
 * leave it in the To-do list for ever. Null when there is nothing to decide.
 * @param {object} finding
 * @param {string} name what the card calls it
 * @returns {{findingId: string, name: string, port: number}|null}
 */
export function exposureDecisionTarget(finding, name) {
  if (finding?.kind !== 'server_exposure' || finding.status === 'decided') return null
  const port = Number(finding.package)
  return { findingId: finding.id, name, port: Number.isInteger(port) && port > 0 ? port : 0 }
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

/**
 * exposureEmptyKey: why there is nothing to show yet, as a catalog key. An
 * inactive server and an unconfirmed fingerprint are said before the check.
 * @param {{active?: boolean, host_key_pinned?: boolean}} target
 * @returns {string}
 */
export function exposureEmptyKey(target) {
  if (!target?.active) return 'servers.state.inactive'
  return target.host_key_pinned ? 'empty.exposure' : 'servers.state.key_unconfirmed'
}

/**
 * exposureShowsFlaw: a row with its path is a flaw shown, so it counts for the
 * guide like a card does. The reserved column is built the same way and counts too.
 * @param {{open: {findingId: string}[], reserved: {findingId: string}[]}} cols
 * @returns {boolean}
 */
export function exposureShowsFlaw(cols) {
  return [...(cols?.open || []), ...(cols?.reserved || [])].some((r) => r.findingId)
}
