// Pure functions behind the curve of the open flaws on the overview (#/):
// the stacked areas by severity of GET /stats/open, the part worked out
// from the old history (dashed) and the equivalent text. A count that
// cannot be read makes the whole curve null, never a curve at 0. No DOM, no
// fetch, no storage. Vitest covers them (openCurveView.test.js).
import { translate } from '../i18n/index.js'
import { severities } from './digestView.js'
import { longDay, shortDay } from './overviewView.js'

/** The size of the drawing, in the units of the SVG viewBox. */
export const curveSize = { width: 320, height: 120 }

/** isCount: a whole number, 0 or more. */
function isCount(v) {
  return Number.isInteger(v) && v >= 0
}

/** localDay is the local Date of a YYYY-MM-DD, null when it cannot be read. */
export function localDay(text) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(text || ''))
  if (!m) return null
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]))
  return d.getDate() === Number(m[3]) ? d : null
}

/** dayKey is a local day as YYYY-MM-DD. */
function dayKey(d) {
  return `${String(d.getFullYear()).padStart(4, '0')}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

/** num writes a coordinate with at most two decimals. */
function num(v) {
  return String(Math.round(v * 100) / 100)
}

/** linePath joins points [x, y] from first to last ('' for none). */
function linePath(points) {
  return points.length ? `M${points.map(([x, y]) => `${num(x)} ${num(y)}`).join(' L')}` : ''
}

/** areaPath closes the area between top (left to right) and bottom (same xs). */
function areaPath(top, bottom) {
  if (!top.length) return ''
  return `${linePath([...top, ...bottom.slice().reverse()])} Z`
}

/**
 * series reads the days of GET /stats/open (oldest first) into a stacked
 * curve: stack is each day with its bands [from, to] per severity, most
 * severe at the bottom; paths has, for each severity with a flaw on some
 * day, the area and the line on its top, split into the reconstructed part
 * (areaReconstructed, lineReconstructed, up to the last reconstructed day)
 * and the rest (area, line), which share that day so they join. summary
 * gives the totals for the equivalent text (null for no day).
 * reconstructedUntil is the last reconstructed day, since the next one (or
 * null). null when a day or a count cannot be read.
 * @param {object[]|null} days
 * @param {{width?: number, height?: number}} [size]
 */
export function series(days, { width = curveSize.width, height = curveSize.height } = {}) {
  if (!Array.isArray(days)) return null
  const stack = []
  for (const d of days) {
    if (!d || !localDay(d.date) || !d.open || typeof d.open !== 'object') return null
    const open = {}
    for (const sev of severities) {
      const n = d.open[sev] === undefined ? 0 : d.open[sev]
      if (!isCount(n)) return null
      open[sev] = n
    }
    const bands = {}
    let under = 0
    for (const sev of severities) {
      bands[sev] = [under, under + open[sev]]
      under += open[sev]
    }
    stack.push({ date: d.date, open, bands, total: under, reconstructed: d.reconstructed === true })
  }
  const max = Math.max(0, ...stack.map((p) => p.total))
  const n = stack.length
  const xOf = (i) => (n === 1 ? [0, width] : [(i * width) / (n - 1)])
  const yOf = (v) => (max ? height - (v / max) * height : height)
  let last = -1
  stack.forEach((p, i) => {
    if (p.reconstructed) last = i
  })
  // edge gives the points of one side of a band over the days from..to.
  const edge = (sev, side, from, to) => {
    const out = []
    for (let i = from; i <= to; i++) for (const x of xOf(i)) out.push([x, yOf(stack[i].bands[sev][side])])
    return out
  }
  const part = (sev, from, to) => (from > to || to < 0 ? { area: '', line: '' } : { area: areaPath(edge(sev, 1, from, to), edge(sev, 0, from, to)), line: linePath(edge(sev, 1, from, to)) })
  const paths = severities.filter((sev) => stack.some((p) => p.open[sev] > 0)).map((sev) => {
    const rec = part(sev, 0, last)
    // The solid part starts on the last reconstructed day, so the two join.
    const solid = last === n - 1 ? { area: '', line: '' } : part(sev, Math.max(0, last), n - 1)
    return { severity: sev, areaReconstructed: rec.area, lineReconstructed: rec.line, area: solid.area, line: solid.line }
  })
  let summary = null
  if (n) {
    let hi = 0
    let lo = 0
    stack.forEach((p, i) => {
      if (p.total >= stack[hi].total) hi = i
      if (p.total <= stack[lo].total) lo = i
    })
    summary = {
      start: stack[0].total, end: stack[n - 1].total, highest: stack[hi].total, lowest: stack[lo].total,
      startDate: stack[0].date, endDate: stack[n - 1].date, highestDate: stack[hi].date, lowestDate: stack[lo].date,
    }
  }
  let since = null
  if (last >= 0) {
    const d = localDay(stack[last].date)
    since = dayKey(new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1))
  }
  return {
    width, height, max, stack, paths, summary,
    reconstructedUntil: last >= 0 ? stack[last].date : null,
    since,
    reconstructedX: last >= 0 ? xOf(last)[xOf(last).length - 1] : null,
  }
}

/** long names a YYYY-MM-DD in full. */
function long(date, lang) {
  return longDay(localDay(date), lang)
}

/**
 * summaryText is the equivalent text of the curve: the start, the end, the
 * highest and the lowest. '' when the curve cannot be read; it says there
 * is no data when there is no day.
 * @param {ReturnType<typeof series>} s
 * @param {string} lang
 */
export function summaryText(s, lang) {
  if (!s) return ''
  const t = (key, params) => translate(lang, key, params)
  if (!s.summary) return t('curve.no_data')
  const m = s.summary
  return [
    t('curve.summary.day', { n: m.start, date: long(m.startDate, lang) }),
    t('curve.summary.day', { n: m.end, date: long(m.endDate, lang) }),
    t('curve.summary.highest', { count: m.highest, date: long(m.highestDate, lang) }),
    t('curve.summary.lowest', { count: m.lowest, date: long(m.lowestDate, lang) }),
  ].join(' ')
}

/**
 * reconstructedNote says the dotted part is worked out from the old history,
 * with the first day Michel kept every change (JJ/MM); '' when none is.
 * @param {ReturnType<typeof series>} s
 * @param {string} lang
 */
export function reconstructedNote(s, lang) {
  if (!s || !s.since) return ''
  return translate(lang, 'curve.reconstructed', { date: shortDay(localDay(s.since), lang) })
}

/** severityNote says every day counts a flaw with its severity of today. */
export function severityNote(lang) {
  return translate(lang, 'curve.severity_today')
}
