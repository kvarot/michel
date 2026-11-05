// Pure functions behind the overview (#/): the four tiles, the weekly new
// and gone flaws, the age of the open flaws and the signals. Every number
// comes from the API; a number that cannot be read is null, never 0, and the
// page says « not read ». No DOM, no fetch, no storage. Vitest covers them
// (overviewView.test.js).
import { severities, severityOf } from './digestView.js'
import { isListedOpen, signals, signalsOf } from './findingsView.js'

const dayMs = 24 * 3600 * 1000

/** isCount: a whole number, 0 or more. */
function isCount(v) {
  return Number.isInteger(v) && v >= 0
}

/**
 * openBySeverity counts the open flaws of every project of the digest, by
 * severity (a label the page does not know counts as unknown). null when
 * the digest or one of its counts cannot be read.
 * @param {object|null} digest GET /today
 * @returns {{total: number, bySeverity: Record<string, number>}|null}
 */
export function openBySeverity(digest) {
  if (!digest || !Array.isArray(digest.projects)) return null
  const bySeverity = Object.fromEntries(severities.map((s) => [s, 0]))
  let total = 0
  for (const p of digest.projects) {
    if (!p || !p.open || typeof p.open !== 'object') return null
    for (const [label, n] of Object.entries(p.open)) {
      if (!isCount(n)) return null
      bySeverity[severityOf(label)] += n
      total += n
    }
  }
  return { total, bySeverity }
}

/**
 * severityShares are the parts of the stacked bar: the severities with a
 * count, most severe first, with their share of the total (0 to 1).
 * @param {{total: number, bySeverity: Record<string, number>}|null} open
 * @returns {{severity: string, n: number, share: number}[]}
 */
export function severityShares(open) {
  if (!open || !open.total) return []
  return severities.filter((s) => open.bySeverity[s] > 0).map((s) => ({ severity: s, n: open.bySeverity[s], share: open.bySeverity[s] / open.total }))
}

/**
 * proposedCount counts the fixes waiting for the person's approval (state
 * proposed). null when the fixes could not be read.
 * @param {object[]|null} attempts GET /fixes
 * @returns {number|null}
 */
export function proposedCount(attempts) {
  if (!Array.isArray(attempts)) return null
  return attempts.filter((a) => a && a.state === 'proposed').length
}

/**
 * provenFixedCount counts the fixes a new check proved (state proven_fixed)
 * whose last change falls in the last days days. An attempt whose time
 * cannot be read is not counted: nothing says it falls in the window. null
 * when the fixes could not be read.
 * @param {object[]|null} attempts GET /fixes
 * @param {Date} now
 * @param {number} [days]
 * @returns {number|null}
 */
export function provenFixedCount(attempts, now, days = 30) {
  if (!Array.isArray(attempts)) return null
  const end = now.getTime()
  const start = end - days * dayMs
  return attempts.filter((a) => {
    if (!a || a.state !== 'proven_fixed') return false
    const t = Date.parse(a.updated_at)
    return !Number.isNaN(t) && t >= start && t <= end
  }).length
}

/**
 * parkSummary is what Michel watches: the projects, the active servers, and
 * the checks that failed (a project whose last scan failed or stopped, a
 * server whose last check failed). Each is null when its list could not be
 * read; failed is null when either could not.
 * @param {object[]|null} projects GET /projects
 * @param {object[]|null} servers GET /targets
 * @returns {{projects: number|null, servers: number|null, failed: number|null}}
 */
export function parkSummary(projects, servers) {
  const p = Array.isArray(projects) ? projects.filter(Boolean) : null
  const s = Array.isArray(servers) ? servers.filter((x) => x && x.active !== false) : null
  const failed = p && s
    ? p.filter((x) => x.last_scan_status === 'failed' || x.last_scan_status === 'interrupted').length
      + s.filter((x) => x.state?.code === 'check_failed').length
    : null
  return { projects: p ? p.length : null, servers: s ? s.length : null, failed }
}

/**
 * weekStart is the Monday at midnight, on the person's clock, of the week of
 * t. It counts calendar days, not 24-hour spans, so a change of hour (summer
 * time) does not move it.
 * @param {Date} t
 * @returns {Date}
 */
export function weekStart(t) {
  const d = new Date(t.getFullYear(), t.getMonth(), t.getDate())
  const back = (d.getDay() + 6) % 7
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() - back)
}

/** dayKey is a local day as YYYY-MM-DD. */
function dayKey(d) {
  return `${String(d.getFullYear()).padStart(4, '0')}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

/**
 * weekKey is the week of t, named by its Monday (YYYY-MM-DD, local).
 * @param {Date} t
 */
export function weekKey(t) {
  return dayKey(weekStart(t))
}

/** runCounts sums the new and gone flaws of one digest sent; null when a count cannot be read. */
function runCounts(run) {
  if (!run || !Array.isArray(run.projects)) return null
  let fresh = 0
  let gone = 0
  for (const p of run.projects) {
    if (!p || !isCount(p.new) || !isCount(p.gone)) return null
    fresh += p.new
    gone += p.gone
  }
  return { fresh, gone }
}

/**
 * weeklyChanges sums, for each of the last weeks weeks (the current one
 * last), the new and gone flaws of the digests sent that week (the week of
 * their until, on the person's clock). A week no digest was sent has null
 * counts and sent 0: nothing was counted that week, it is not « 0 ». A
 * digest whose counts cannot be read makes its week null too (unread true).
 * A digest whose time cannot be read is left out. null when the digests
 * could not be read.
 * @param {object[]|null} runs GET /digests?last=100
 * @param {Date} now
 * @param {number} [weeks]
 * @returns {{key: string, start: Date, fresh: number|null, gone: number|null, sent: number, unread: boolean}[]|null}
 */
export function weeklyChanges(runs, now, weeks = 8) {
  if (!Array.isArray(runs)) return null
  const current = weekStart(now)
  const out = []
  for (let i = weeks - 1; i >= 0; i--) {
    const start = new Date(current.getFullYear(), current.getMonth(), current.getDate() - 7 * i)
    out.push({ key: dayKey(start), start, fresh: null, gone: null, sent: 0, unread: false })
  }
  const byKey = new Map(out.map((w) => [w.key, w]))
  for (const run of runs) {
    const t = new Date(run?.until)
    if (Number.isNaN(t.getTime())) continue
    const w = byKey.get(weekKey(t))
    if (!w) continue
    w.sent++
    const c = runCounts(run)
    if (!c) w.unread = true
    if (w.unread) continue
    w.fresh = (w.fresh || 0) + c.fresh
    w.gone = (w.gone || 0) + c.gone
  }
  for (const w of out) {
    if (w.unread) {
      w.fresh = null
      w.gone = null
    }
  }
  return out
}

/** The age buckets of the open flaws, in days since first seen. */
export const ageBuckets = [
  { key: 'd0_30', min: 0, max: 30 },
  { key: 'd31_90', min: 31, max: 90 },
  { key: 'd91_180', min: 91, max: 180 },
  { key: 'd181', min: 181, max: Infinity },
]

/**
 * ageOf is the number of whole days between first seen and now (0 the
 * first day); null when the time cannot be read. A time ahead of now (a
 * clock behind) counts as 0.
 * @param {string} firstSeen RFC 3339
 * @param {Date} now
 */
export function ageOf(firstSeen, now) {
  const t = Date.parse(firstSeen)
  if (Number.isNaN(t) || !/^\d{4}-\d{2}-\d{2}/.test(String(firstSeen || ''))) return null
  return Math.max(0, Math.floor((now.getTime() - t) / dayMs))
}

/**
 * ageCounts counts the open flaws (isListedOpen) by how long they have been
 * open. unknown counts those whose first time cannot be read: they are
 * named apart, not put in a bucket.
 * @param {object[]} findings FindingView of every project
 * @param {Date} now
 * @returns {{buckets: {key: string, n: number}[], unknown: number, total: number}}
 */
export function ageCounts(findings, now) {
  const counts = Object.fromEntries(ageBuckets.map((b) => [b.key, 0]))
  let unknown = 0
  let total = 0
  for (const f of findings || []) {
    if (!f || !isListedOpen(f)) continue
    total++
    const age = ageOf(f.first_seen_at, now)
    if (age === null) {
      unknown++
      continue
    }
    counts[ageBuckets.find((b) => age >= b.min && age <= b.max).key]++
  }
  return { buckets: ageBuckets.map((b) => ({ key: b.key, n: counts[b.key] })), unknown, total }
}

/**
 * signalCounts counts the open flaws carrying each signal (signals order).
 * @param {object[]} findings FindingView of every project
 * @returns {{signal: string, n: number}[]}
 */
export function signalCounts(findings) {
  const counts = Object.fromEntries(signals.map((s) => [s, 0]))
  for (const f of findings || []) {
    if (!f || !isListedOpen(f)) continue
    for (const s of signalsOf(f)) counts[s]++
  }
  return signals.map((signal) => ({ signal, n: counts[signal] }))
}

/**
 * allListed flattens the lists that could be read ({name: list|null}).
 * @param {Record<string, object[]|null>} lists
 * @returns {object[]}
 */
export function allListed(lists) {
  return Object.values(lists || {}).filter(Array.isArray).flat().filter(Boolean)
}

/**
 * barHeight is the height of a bar of the weekly chart, out of full, for n
 * against the largest count max. A count that was read and is above 0
 * never falls under 2, so it stays visible.
 * @param {number|null} n
 * @param {number} max
 * @param {number} full
 */
export function barHeight(n, max, full) {
  if (!n || !max) return 0
  return Math.max(2, Math.round((n / max) * full))
}

/** weeklyMax is the largest new or gone count of the weeks (0 when none was read). */
export function weeklyMax(weeks) {
  return Math.max(0, ...(weeks || []).flatMap((w) => [w.fresh || 0, w.gone || 0]))
}
