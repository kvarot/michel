// Pure functions behind the timeline of a flaw on its guided sheet
// (#/fix?finding=<id>): one line per entry of GET /findings/{id}/timeline,
// newest first, in plain words. No DOM, no fetch, no storage. Vitest covers
// them (timelineView.test.js).
import { translate } from '../i18n/index.js'
import { longDay, shortDay } from './overviewView.js'

/** foldAt is the number of lines shown before the rest is folded. */
export const foldAt = 10

/** The reasons the catalog already says (reason.*), shared with the page of a project. */
const knownReasons = ['severity_changed', 'fixed_version_changed', 'due_reached', 'reappeared_changed']
/** The reasons only the timeline says. */
const timelineReasons = ['redecided', 'kev_changed']
/** The states of a fix attempt the timeline has words for. */
const attemptStates = ['preparing', 'running', 'proposed', 'approved', 'refused', 'applied', 'proven_fixed', 'inconclusive', 'failed', 'withdrawn', 'superseded', 'held', 'unknown']
const actions = ['fix', 'defer', 'ignore']
const authors = ['web', 'cli']

/** readTime is the Date of an RFC 3339 text, null when it cannot be read. */
function readTime(at) {
  if (!/^\d{4}-\d{2}-\d{2}/.test(String(at || ''))) return null
  const t = new Date(at)
  return Number.isNaN(t.getTime()) ? null : t
}

/** sameDay tells whether a and b fall on the same day of the person's clock. */
function sameDay(a, b) {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate()
}

/**
 * lineDate names the moment of an entry on the person's clock: « aujourd'hui
 * à 09:05 », « hier à 23:30 », or the day in full with the hour.
 * @param {string} at RFC 3339
 * @param {string} lang
 * @param {Date} now
 */
export function lineDate(at, lang, now) {
  const t = readTime(at)
  if (!t) return translate(lang, 'timeline.unknown_date')
  const time = `${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}`
  const yesterday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1)
  if (sameDay(t, now)) return translate(lang, 'timeline.today', { time })
  if (sameDay(t, yesterday)) return translate(lang, 'timeline.yesterday', { time })
  return translate(lang, 'timeline.on', { date: longDay(t, lang), time })
}

/** dayText is the day of an RFC 3339 text in full, '' when it cannot be read. */
function dayText(at, lang) {
  const t = readTime(at)
  return t ? longDay(t, lang) : ''
}

/** reasonText says why a decision stopped holding, in plain words. */
function reasonText(reason, lang) {
  if (knownReasons.includes(reason)) return translate(lang, `reason.${reason}`)
  if (timelineReasons.includes(reason)) return translate(lang, `timeline.reason.${reason}`)
  return translate(lang, 'reason.unknown')
}

/** decisionText says a decision: its action, who took it, and its end. */
function decisionText(d, lang, advanced) {
  const t = (key, params) => translate(lang, key, params)
  const due = dayText(d.due, lang)
  let text
  if (!actions.includes(d.action)) text = t('timeline.decision.other')
  else if (d.action === 'defer' && due) text = t('timeline.decision.defer_until', { date: due })
  else text = t(`timeline.decision.${d.action}`)
  if (authors.includes(d.author)) text += t(`timeline.author.${d.author}`)
  else if (advanced && d.author) text += t('timeline.author.other', { author: d.author })
  const ended = dayText(d.superseded_at, lang)
  if (ended && d.reason === 'redecided') text += t('timeline.replaced', { date: ended })
  else if (ended) text += t('timeline.ended', { date: ended, reason: reasonText(d.reason, lang) })
  return text
}

/** attemptText says one step of a fix attempt; advanced mode names the attempt. */
function attemptText(d, lang, advanced) {
  const state = attemptStates.includes(d.state) ? d.state : 'other'
  const text = translate(lang, `timeline.attempt.${state}`)
  if (!advanced || !d.attempt_id) return text
  return `${text} (${translate(lang, 'timeline.attempt_id', { id: d.attempt_id })})`
}

/** entryText says one entry of the timeline in plain words. */
function entryText(e, lang, advanced) {
  const d = e.detail && typeof e.detail === 'object' ? e.detail : {}
  switch (e.kind) {
    case 'seen':
    case 'gone':
    case 'back':
      return translate(lang, `timeline.${e.kind}`)
    case 'reopened':
      return translate(lang, 'timeline.reopened', { reason: reasonText(d.reason, lang) })
    case 'decision':
      return decisionText(d, lang, advanced)
    case 'attempt':
      return attemptText(d, lang, advanced)
    default:
      return translate(lang, 'timeline.other')
  }
}

/**
 * lines turns the entries of GET /findings/{id}/timeline (newest first, the
 * order is kept) into lines {at, kind, date, text, reconstructed}. Advanced
 * mode adds the id of a fix attempt and names an author Michel does not
 * know. Up to foldAt lines it returns the list; above, {shown, hidden}: the
 * foldAt newest and the rest. null when the answer cannot be read.
 * @param {object[]|null} entries
 * @param {string} lang
 * @param {Date} now
 * @param {{advanced?: boolean}} [opts]
 */
export function lines(entries, lang, now, { advanced = false } = {}) {
  if (!Array.isArray(entries)) return null
  const all = entries.filter((e) => e && typeof e === 'object').map((e) => ({
    at: e.at,
    kind: e.kind,
    date: lineDate(e.at, lang, now),
    text: entryText(e, lang, advanced),
    reconstructed: e.reconstructed === true,
  }))
  if (all.length <= foldAt) return all
  return { shown: all.slice(0, foldAt), hidden: all.slice(foldAt) }
}

/**
 * fold gives the answer of lines one shape for the page: {shown, hidden},
 * hidden empty at foldAt lines or fewer. null stays null.
 * @param {object[]|{shown: object[], hidden: object[]}|null} out
 */
export function fold(out) {
  if (!out) return null
  return Array.isArray(out) ? { shown: out, hidden: [] } : out
}

/**
 * historyNote says, when an entry is reconstructed, from when Michel keeps
 * every change (the history start, JJ/MM); '' when no entry is.
 * @param {object[]|null} entries
 * @param {string} historyStart RFC 3339
 * @param {string} lang
 */
export function historyNote(entries, historyStart, lang) {
  if (!Array.isArray(entries) || !entries.some((e) => e && e.reconstructed === true)) return ''
  const t = readTime(historyStart)
  return t ? translate(lang, 'timeline.note', { date: shortDay(t, lang) }) : translate(lang, 'timeline.note_nodate')
}
