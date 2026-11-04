// Pure functions behind the "Journaux" block of the server sheet and the
// log badges of the servers list: no DOM, no fetch, no storage. Vitest covers
// them (serverLogsView.test.js). The wording is for someone who knows nothing
// of computing: the recommended choice comes first and says so.
import { translate } from '../i18n/index.js'
import { agoText } from './sourcesView.js'

/** The levels of an error, the worst first (the API's own words). */
export const levelOrder = ['critical', 'error', 'warning', 'info']

/** The formats of a log a person can pick, the common ones first. */
export const formats = ['php', 'postgres', 'monolog', 'json', 'text']

/** The routes of an alert rule, the recommended one is the API's default for the level. */
export const routes = ['immediate', 'digest', 'ignored']

// The reading intervals offered: 5 min is the recommended one and comes first.
const intervalValues = ['5m', '1m', '15m', '30m', '1h', '6h', '24h']
const retentionValues = [90, 30, 7, 180, 365]
const recommendedRetention = 90
const slowAfterMinutes = 10

/** @param {string} lang @param {string} key @param {object} [params] */
function t(lang, key, params) {
  return translate(lang, `logs.${key}`, params)
}

/** @param {string} format @param {string} lang @returns {string} the kind of log in plain words. */
export function formatLabel(format, lang) {
  return formats.includes(format) ? t(lang, `format.${format}`) : String(format || '')
}

/** @param {string} level @param {string} lang @returns {string} the level of an error in plain words. */
export function levelLabel(level, lang) {
  return levelOrder.includes(level) ? t(lang, `level.${level}`) : String(level || '')
}

/** @param {string} level @returns {string} the severity class (m-sev--…) that looks like this level. */
export function levelSeverity(level) {
  return { critical: 'critical', error: 'high', warning: 'medium', info: 'low' }[level] || 'unknown'
}

/** @param {string} status @param {string} lang @returns {string} the status of an error in plain words. */
export function statusLabel(status, lang) {
  return ['new', 'seen', 'resolved', 'reopened', 'ignored'].includes(status) ? t(lang, `status.${status}`) : String(status || '')
}

/**
 * errorGroups puts the errors in one group per level, the worst level first;
 * a level without error, and an unknown level, are left out.
 * @param {{level: string}[]} errors GET /logs/errors → errors
 * @returns {{level: string, errors: object[]}[]}
 */
export function errorGroups(errors) {
  const list = Array.isArray(errors) ? errors : []
  return levelOrder.map((level) => ({ level, errors: list.filter((e) => e.level === level) })).filter((g) => g.errors.length)
}

/**
 * privacyChoices lists, for each privacy setting, the choices a person can
 * pick: the recommended one first and marked « recommandé », then the others.
 * The choice in force is marked current (a retention outside the list is
 * added). A choice away from the recommendation is strong on a health (hds)
 * server. The text of alerts is disabled while no text is kept.
 * @param {{store_text: boolean, alert_text: boolean, retention_days: number}} settings GET /logs/settings
 * @param {string} kind the kind of the server (vps, shared, hds)
 * @param {string} lang
 * @returns {{key: string, choices: {value: boolean|number, label: string, recommended: boolean, current: boolean, strong: boolean, disabled: boolean}[]}[]}
 */
export function privacyChoices(settings, kind, lang) {
  const st = settings || {}
  const mark = (label, recommended) => (recommended ? `${label} (${t(lang, 'recommended')})` : label)
  const make = (value, label, recommended, current, extra = {}) => ({
    value, label: mark(label, recommended), recommended, current, strong: kind === 'hds' && !recommended, disabled: false, ...extra,
  })
  const text = [
    make(false, t(lang, 'choice.store_text.no'), true, !st.store_text),
    make(true, t(lang, 'choice.store_text.yes'), false, !!st.store_text),
  ]
  const alert = [
    make(false, t(lang, 'choice.alert_text.no'), true, !st.alert_text),
    make(true, t(lang, 'choice.alert_text.yes'), false, !!st.alert_text, { disabled: !st.store_text }),
  ]
  const days = [...retentionValues]
  if (Number.isInteger(st.retention_days) && !days.includes(st.retention_days)) days.push(st.retention_days)
  const retention = days.map((n) => make(n, t(lang, 'choice.retention', { n }), n === recommendedRetention, n === st.retention_days))
  return [
    { key: 'store_text', choices: text },
    { key: 'alert_text', choices: alert },
    { key: 'retention', choices: retention },
  ]
}

/**
 * deviationWarning is the question put before a setting moves away from the
 * recommended choice. The risk itself comes from the API (it answers 409 with
 * it); this is the title, and on a health (hds) server the stronger sentence:
 * the data would leave the health hosting, and the responsibility is the
 * user's. Michel does not block.
 * @param {string} key store_text, alert_text or retention (the API's deviation codes)
 * @param {string} kind the kind of the server
 * @param {string} lang
 * @returns {{title: string, health: string, strong: boolean}}
 */
export function deviationWarning(key, kind, lang) {
  const known = ['store_text', 'alert_text', 'retention'].includes(key)
  const strong = kind === 'hds'
  return {
    title: t(lang, known ? `deviation.${key}.title` : 'deviation.other.title'),
    health: strong ? t(lang, 'deviation.health') : '',
    strong,
  }
}

/**
 * minutesOf reads an interval the way the API writes it (5m, 2h, 1h30m0s):
 * the minutes, or -1 for "manual" and for what it cannot read.
 * @param {string} duration
 */
function minutesOf(duration) {
  const m = String(duration || '').trim().match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/)
  if (!m || !String(duration).trim()) return -1
  return Number(m[1] || 0) * 60 + Number(m[2] || 0) + Number(m[3] || 0) / 60
}

/**
 * intervalNote says in plain words what a reading interval costs: by hand,
 * nobody is warned in between, and the sentence follows the mode (the
 * command's name in advanced mode, the plain words otherwise: the page has
 * no button for it). Otherwise the API's own note wins, and above 10 minutes
 * a local sentence stands in when the API sent none. "" when there is nothing
 * to say.
 * @param {{interval?: string, interval_note?: string}} settings GET /logs/settings
 * @param {boolean} advanced the advanced mode
 * @param {string} lang
 */
export function intervalNote(settings, advanced, lang) {
  const st = settings || {}
  if (String(st.interval) === 'manual') return t(lang, advanced ? 'interval.manual_advanced' : 'interval.manual_simple')
  if (st.interval_note) return st.interval_note
  return minutesOf(st.interval) > slowAfterMinutes ? t(lang, 'interval.slow') : ''
}

/**
 * domId makes a string safe to use inside an id and in aria-describedby
 * (which splits on spaces): letters, digits, - and _ only, and a hash of the
 * original so two different paths never share one.
 * @param {string} text
 * @returns {string}
 */
export function domId(text) {
  const s = String(text ?? '')
  let h = 5381
  for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0
  return `${s.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 40)}-${h.toString(36)}`
}

/**
 * settingsSaveOutcome reads the failure of a settings save: a 409
 * logs.confirm_needed is a question for the user (the risk comes with it), any
 * other failure is an error, none is ok.
 * @param {any} err what api.patch threw, or nothing
 * @returns {{kind: 'ok'} | {kind: 'confirm', deviations: object[], health: string} | {kind: 'error', error: any}}
 */
export function settingsSaveOutcome(err) {
  if (!err) return { kind: 'ok' }
  if (err.status === 409 && err.data?.code === 'logs.confirm_needed') {
    return { kind: 'confirm', deviations: err.data.deviations || [], health: err.data.health || '' }
  }
  return { kind: 'error', error: err }
}

/** @param {string} value "5m", "2h", "manual" @param {string} lang @returns {string} the interval in words. */
export function intervalText(value, lang) {
  if (value === 'manual') return t(lang, 'interval.choice.manual')
  const min = minutesOf(value)
  if (min < 0) return String(value || '')
  if (min % 60 === 0) return t(lang, 'interval.choice.hours', { n: min / 60 })
  return t(lang, 'interval.choice.minutes', { n: Math.round(min) })
}

/**
 * intervalChoices are the reading intervals offered, 5 minutes first and
 * marked recommended, by hand last; an interval in force that is not in the
 * list is added before « à la main ».
 * @param {string} current the interval in force
 * @param {string} lang
 * @returns {{value: string, title: string}[]}
 */
export function intervalChoices(current, lang) {
  const values = [...intervalValues]
  if (current && current !== 'manual' && !values.includes(current)) values.push(current)
  values.push('manual')
  return values.map((value, i) => ({ value, title: i === 0 ? `${intervalText(value, lang)} (${t(lang, 'recommended')})` : intervalText(value, lang) }))
}

/**
 * readState says where the reading of one log stands: when it last succeeded,
 * and the files Michel could not see, each as « Non vu : … ».
 * @param {{active?: boolean, last_read_at?: string, unseen?: {what: string, reason: string}[]}} source one of GET /logs/sources
 * @param {Date} now
 * @param {string} lang
 * @returns {{line: string, unseen: {what: string, reason: string, text: string}[]}}
 */
export function readState(source, now, lang) {
  const s = source || {}
  const ago = s.last_read_at ? agoText(s.last_read_at, now, (key, params) => translate(lang, key, params)) : ''
  let line
  if (ago) line = t(lang, 'read.last', { ago })
  else line = s.active ? t(lang, 'read.never') : t(lang, 'read.off')
  const unseen = (Array.isArray(s.unseen) ? s.unseen : []).map((u) => ({ what: u.what, reason: u.reason, text: t(lang, 'read.unseen', { what: u.what, reason: u.reason }) }))
  return { line, unseen }
}

/**
 * channelNotes are the warnings about who can be told: nobody (a log is read
 * but no way to warn exists), and the text message limit shared with flaw
 * alerts.
 * @param {{noChannel?: boolean, sms?: boolean}} state
 * @param {string} lang
 * @returns {string[]}
 */
export function channelNotes(state, lang) {
  const out = []
  if (state?.noChannel) out.push(t(lang, 'channel.none'))
  if (state?.sms) out.push(t(lang, 'channel.sms'))
  return out
}

/**
 * logBadges are the badges of a server in the list and on the sheet: new
 * errors, nobody to tell, a privacy setting away from the recommendation.
 * @param {{log_new?: number, log_no_channel?: boolean, log_deviations?: string[]}} target a TargetView
 * @param {string} lang
 * @returns {{key: string, text: string}[]}
 */
export function logBadges(target, lang) {
  const out = []
  const n = Number(target?.log_new) || 0
  if (n > 0) out.push({ key: 'new', text: t(lang, 'badge.new', { n }) })
  if (target?.log_no_channel) out.push({ key: 'no_channel', text: t(lang, 'badge.no_channel') })
  if ((target?.log_deviations || []).length) out.push({ key: 'deviation', text: t(lang, 'badge.deviation') })
  return out
}

/**
 * recommendedRoute is how Michel warns by default for a level (spec § 8.1):
 * at once for a critical error on a prod server, in the morning summary for
 * errors, never for warnings and information.
 * @param {string} level @param {string} env prod, preprod or dev
 */
export function recommendedRoute(level, env) {
  if (level === 'critical') return env === 'prod' ? 'immediate' : 'digest'
  return level === 'error' ? 'digest' : 'ignored'
}

/**
 * routeChoices are the ways to be warned about one level of error, the
 * recommended one first and marked.
 * @param {string} level critical, error, warning or info
 * @param {string} env the environment of the server
 * @param {string} lang
 * @returns {{value: string, title: string, recommended: boolean}[]}
 */
export function routeChoices(level, env, lang) {
  const rec = recommendedRoute(level, env)
  return [rec, ...routes.filter((r) => r !== rec)].map((value) => ({
    value, recommended: value === rec, title: value === rec ? `${t(lang, `route.${value}`)} (${t(lang, 'recommended')})` : t(lang, `route.${value}`),
  }))
}
