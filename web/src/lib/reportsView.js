// Pure functions behind the Reports page (#/reports): the week or the month
// shown, its address, the lead sentence and the lines of the tables of
// GET /reports. A count that cannot be read is null (« non lu »), never 0.
// No DOM, no fetch, no storage. Vitest covers them (reportsView.test.js).
import { translate } from '../i18n/index.js'
import { severities } from './digestView.js'
import { dayKey, localDay } from './openCurveView.js'
import { longDay } from './overviewView.js'

/** The kinds of period a report covers. */
export const periodKinds = ['week', 'month']

/** isCount: a whole number, 0 or more. */
function isCount(v) {
  return Number.isInteger(v) && v >= 0
}

/** count is v when it is a count, null otherwise. */
function count(v) {
  return isCount(v) ? v : null
}

/** toDay reads a Date or a YYYY-MM-DD as a local day at 00:00, null when it cannot. */
function toDay(v) {
  if (v instanceof Date && !Number.isNaN(v.getTime())) return new Date(v.getFullYear(), v.getMonth(), v.getDate())
  return localDay(v)
}

/** plus is the local day n days after d (calendar days: a change of hour does not count). */
function plus(d, n) {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() + n)
}

/** bounds is the first and the last day of the period of kind holding d. */
function bounds(kind, d) {
  if (kind === 'month') return [new Date(d.getFullYear(), d.getMonth(), 1), new Date(d.getFullYear(), d.getMonth() + 1, 0)]
  // getDay: 0 is Sunday. A week starts on Monday.
  const monday = plus(d, -((d.getDay() + 6) % 7))
  return [monday, plus(monday, 6)]
}

/** monthName names the month of d with its year, lower case in French (« octobre 2026 »). */
function monthName(d, lang) {
  const name = new Intl.DateTimeFormat(lang === 'fr' ? 'fr-FR' : 'en-GB', { month: 'long', year: 'numeric' }).format(d)
  return lang === 'fr' ? name.toLocaleLowerCase('fr-FR') : name
}

/** capital puts the first letter in upper case. */
function capital(s) {
  return s ? s[0].toUpperCase() + s.slice(1) : s
}

/**
 * period is the week (Monday to Sunday) or the month (the 1st to its last
 * day) holding the local day at, in local time. With no day, or one that
 * cannot be read, it is the previous complete period; a day after the
 * current period gives the current period: the page never offers one in
 * the future. prev and next are the first day of the periods around it,
 * next null for the current period. An unknown kind is a week.
 * @param {'week'|'month'} kind
 * @param {string} [at] YYYY-MM-DD
 * @param {string|Date} [today]
 * @param {string} [lang]
 * @returns {{kind: string, from: string, to: string, label: string, current: boolean, prev: string, next: string|null}}
 */
export function period(kind, at, today = new Date(), lang = 'en') {
  const k = periodKinds.includes(kind) ? kind : 'week'
  const now = toDay(today) || toDay(new Date())
  const [curFrom, curTo] = bounds(k, now)
  let day = toDay(at)
  if (!day) day = plus(curFrom, -1)
  if (day > curTo) day = now
  const [from, to] = bounds(k, day)
  const current = from.getTime() === curFrom.getTime()
  const label = k === 'month'
    ? capital(monthName(from, lang))
    : translate(lang, 'reports.week_label', { from: longDay(from, lang), to: longDay(to, lang) })
  return {
    kind: k,
    from: dayKey(from),
    to: dayKey(to),
    label,
    current,
    prev: dayKey(bounds(k, plus(from, -1))[0]),
    next: current ? null : dayKey(plus(to, 1)),
  }
}

/**
 * reportsRoute reads #/reports?period=…&at=… ({period, at}); null for
 * another page. An unknown period is a week.
 * @param {string} hash
 */
export function reportsRoute(hash) {
  const m = /^#\/reports(?:\?([^#]*))?$/.exec(String(hash || ''))
  if (!m) return null
  const q = new URLSearchParams(m[1] || '')
  const kind = q.get('period')
  return { period: periodKinds.includes(kind) ? kind : 'week', at: q.get('at') || '' }
}

/** reportsHash is the address of a period: its kind and one of its days. */
export function reportsHash(kind, at) {
  const q = new URLSearchParams({ period: periodKinds.includes(kind) ? kind : 'week' })
  if (at) q.set('at', at)
  return `#/reports?${q.toString()}`
}

/** total sums a map by severity, null when it or one of its counts cannot be read. */
function total(m) {
  if (!m || typeof m !== 'object') return null
  let n = 0
  for (const v of Object.values(m)) {
    if (!isCount(v)) return null
    n += v
  }
  return n
}

/** sumOf adds counts, null when one is null. */
function sumOf(...vs) {
  return vs.some((v) => v === null) ? null : vs.reduce((a, b) => a + b, 0)
}

/** sevCount is the count of sev in the map m, null when it cannot be read (absent is 0). */
function sevCount(m, sev) {
  if (!m || typeof m !== 'object') return null
  return m[sev] === undefined ? 0 : count(m[sev])
}

/**
 * leadOf names the period of a report for the lead sentence: « Cette
 * semaine », « Ce mois-ci » for the current period, else the week or the
 * month, else its two days.
 */
function leadOf(report, lang, today) {
  const t = (key, params) => translate(lang, key, params)
  const from = localDay(report.from)
  const to = localDay(report.to)
  if (!from || !to) return t('reports.lead.period')
  for (const k of periodKinds) {
    const [a, b] = bounds(k, from)
    if (dayKey(a) !== report.from || dayKey(b) !== report.to) continue
    const now = toDay(today)
    const current = !!now && now >= a && now <= b
    if (current) return t(`reports.lead.${k}_current`)
    if (k === 'month') return t('reports.lead.month', { month: monthName(from, lang) })
    return t('reports.lead.week', { from: longDay(from, lang), to: longDay(to, lang) })
  }
  return t('reports.lead.range', { from: longDay(from, lang), to: longDay(to, lang) })
}

/**
 * summary is the lead sentence of a report: the flaws found, the flaws
 * gone (fixed by Michel or elsewhere) and the fixes submitted for approval
 * in the period (« Cette semaine : 4 failles trouvées, 6 corrigées, 2
 * correctifs proposés à ta validation. »). A count that cannot be read
 * says « non lu ». '' with no report.
 * @param {object|null} report GET /reports
 * @param {string} lang
 * @param {string|Date} [today]
 */
export function summary(report, lang, today = new Date()) {
  if (!report || typeof report !== 'object') return ''
  const t = (key, params) => translate(lang, key, params)
  const part = (key, n) => (n === null ? t(`reports.summary.${key}_unread`) : t(`reports.summary.${key}`, { n }))
  const found = total(report.found)
  const gone = sumOf(total(report.gone_by_michel), total(report.gone_elsewhere))
  const proposed = count(report.fixes?.proposed)
  return t('reports.summary', {
    lead: leadOf(report, lang, today),
    parts: [part('found', found), part('fixed', gone), part('proposed', proposed)].join(', '),
  })
}

/**
 * severityRows are the lines of the table by severity, then the totals
 * (severity 'total'): found, gone by Michel, gone elsewhere, open at the
 * start and at the end. A count that cannot be read is null.
 * @param {object} report GET /reports
 */
export function severityRows(report) {
  const r = report || {}
  const cols = { found: r.found, goneByMichel: r.gone_by_michel, goneElsewhere: r.gone_elsewhere, openStart: r.open_start, openEnd: r.open_end }
  const rows = severities.map((sev) => {
    const row = { severity: sev }
    for (const [k, m] of Object.entries(cols)) row[k] = sevCount(m, sev)
    return row
  })
  const sum = { severity: 'total' }
  for (const k of Object.keys(cols)) sum[k] = sumOf(...rows.map((x) => x[k]))
  return [...rows, sum]
}

/** decisionRows are the decisions taken, by action ({action, n}). */
export function decisionRows(report) {
  const d = report?.decisions
  return ['fix', 'defer', 'ignore'].map((action) => ({ action, n: d && typeof d === 'object' ? (d[action] === undefined ? 0 : count(d[action])) : null }))
}

/** fixRows are the fixes proposed, applied and proven fixed ({key, n}). */
export function fixRows(report) {
  const f = report?.fixes
  return ['proposed', 'applied', 'proven'].map((key) => ({ key, n: f && typeof f === 'object' ? count(f[key]) : null }))
}

/**
 * checkRows are the checks done and failed, for the projects and the
 * servers. Michel keeps nothing of a failed server check: its count is
 * null (« non lu »), never 0.
 * @param {object} report GET /reports
 */
export function checkRows(report) {
  const c = report?.checks
  return ['projects', 'servers'].map((key) => ({ key, done: count(c?.[key]?.done), failed: count(c?.[key]?.failed) }))
}

/** serverCounts are the server flaws found and closed, counted apart. */
export function serverCounts(report) {
  return { found: count(report?.servers?.found), closed: count(report?.servers?.closed) }
}

/**
 * projectRows is one line per project; null when the list cannot be read.
 * @param {object} report GET /reports
 */
export function projectRows(report) {
  if (!Array.isArray(report?.projects)) return null
  return report.projects.map((p) => ({
    name: String(p?.name || ''),
    found: count(p?.found),
    gone: count(p?.gone),
    openEnd: count(p?.open_end),
    decisions: count(p?.decisions),
  }))
}

/**
 * oldestLine names the flaw still open the longest at the end of the
 * period, the day it was first seen and the link to its page; null when
 * none is open.
 * @param {object} report GET /reports
 * @param {string} lang
 */
export function oldestLine(report, lang) {
  const o = report?.oldest_open
  if (!o || !o.finding_id) return null
  const at = new Date(o.first_seen_at)
  const id = o.osv_id ? ` (${o.osv_id})` : ''
  return {
    name: `${o.package || ''}${id}`.trim(),
    since: Number.isNaN(at.getTime()) ? '' : longDay(at, lang),
    href: `#/fix?finding=${encodeURIComponent(o.finding_id)}`,
  }
}
