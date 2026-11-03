// Pure functions behind the Today page: no DOM, no fetch, no storage.
// Vitest covers them (digestView.test.js).
import { translate } from '../i18n/index.js'

/** Severity labels, most severe first (as the API sorts them). */
export const severities = ['critical', 'high', 'medium', 'low', 'unknown']

/** Kinds of attention items, in the order they show for equal severity. */
const kinds = ['new', 'superseded', 'due']

/** @param {string} s @returns {number} rank of s, unknown labels last. */
export function severityRank(s) {
  const i = severities.indexOf(s)
  return i < 0 ? severities.length - 1 : i
}

/** @param {string} s @returns {string} one of severities. */
export function severityOf(s) {
  return severities[severityRank(s)]
}

/**
 * groupAttention flattens each project's new packages, decisions to review
 * and due deferrals into one list, most severe first, keeping the projects in
 * the digest's order (a project with nothing gets an empty list). A decision
 * to review or a deferral has its finding's severity; a digest without it
 * (older server) falls back to a new package of the same name, then "unknown". text is the "what" sentence for new packages,
 * the reason code for decisions to review and the due date for deferrals.
 * decided is the action already taken on a new package ("" when not decided).
 * kev and malicious mark a line one of whose findings is exploited in the
 * wild or a malicious package: a new package carries them (with epss, its
 * highest exploitation score, and findingKind, the sort of its findings); a
 * decision to review or a deferral takes them from digest.exploited.
 * @returns {{project: string, items: {kind: string, package: string, severity: string, text: string, findingIds: string[], kev: boolean, malicious: boolean, epss: number, findingKind: string}[]}[]}
 */
export function groupAttention(digest) {
  if (!digest || !Array.isArray(digest.projects)) return []
  const exploited = {}
  for (const e of digest.exploited || []) exploited[e.finding_id] = e
  const marks = (ids) => ({
    kev: ids.some((id) => exploited[id] && !!exploited[id].kev_added),
    malicious: ids.some((id) => exploited[id] && !!exploited[id].malicious),
  })
  return digest.projects.map((p) => {
    const fresh = p.new || []
    const severityByName = {}
    for (const pkg of fresh) {
      const sev = severityOf(pkg.worst_severity)
      const known = severityByName[pkg.name]
      if (known === undefined || severityRank(sev) < severityRank(known)) severityByName[pkg.name] = sev
    }
    const items = []
    for (const pkg of fresh) {
      items.push({
        kind: 'new', package: pkg.name, severity: severityOf(pkg.worst_severity), text: pkg.what || '',
        findingIds: pkg.finding_ids || [], osvIds: pkg.osv_ids || [], installed: pkg.installed || '', target: pkg.target || '',
        decided: pkg.decided || '', kev: !!pkg.kev, malicious: !!pkg.malicious, epss: pkg.epss || 0,
        findingKind: pkg.kind || 'dependency',
      })
    }
    for (const s of p.superseded || []) {
      items.push({
        kind: 'superseded', package: s.package, severity: s.severity ? severityOf(s.severity) : severityByName[s.package] || 'unknown', text: s.reason || '',
        findingIds: s.finding_id ? [s.finding_id] : [], osvIds: s.osv_id ? [s.osv_id] : [], previousAction: s.previous_action || '',
      })
    }
    for (const d of p.due || []) {
      items.push({
        kind: 'due', package: d.package, severity: d.severity ? severityOf(d.severity) : severityByName[d.package] || 'unknown', text: d.due_at || '',
        findingIds: d.finding_id ? [d.finding_id] : [], osvIds: d.osv_id ? [d.osv_id] : [], overdue: !!d.overdue,
      })
    }
    for (const item of items) {
      if (item.kind !== 'new') Object.assign(item, marks(item.findingIds), { epss: 0, findingKind: 'dependency' })
    }
    const order = items.map((item, i) => ({ item, i }))
    order.sort((a, b) =>
      severityRank(a.item.severity) - severityRank(b.item.severity)
      || kinds.indexOf(a.item.kind) - kinds.indexOf(b.item.kind)
      || a.i - b.i)
    return { project: p.name, items: order.map((o) => o.item) }
  })
}

/**
 * formatDate shows the calendar day of an RFC 3339 time or a YYYY-MM-DD
 * date, in UTC as the server stores it: 22/11/2026 in French, 2026-11-22 in
 * English. Anything else gives "".
 */
export function formatDate(iso, lang) {
  const s = String(iso || '')
  if (!/^\d{4}-\d{2}-\d{2}($|T)/.test(s)) return ''
  const t = new Date(s.length === 10 ? `${s}T00:00:00Z` : s)
  if (Number.isNaN(t.getTime())) return ''
  const y = String(t.getUTCFullYear()).padStart(4, '0')
  const mo = String(t.getUTCMonth() + 1).padStart(2, '0')
  const d = String(t.getUTCDate()).padStart(2, '0')
  return lang === 'fr' ? `${d}/${mo}/${y}` : `${y}-${mo}-${d}`
}

/**
 * localDay writes the calendar day of a time on the user's clock: the API sends
 * UTC, and the day a person remembers is their own. A date alone stays as it is.
 * @param {string} iso @param {string} lang @returns {string}
 */
export function localDay(iso, lang) {
  if (!/^\d{4}-\d{2}-\d{2}T/.test(String(iso || ''))) return formatDate(iso, lang)
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const y = String(d.getFullYear()).padStart(4, '0')
  const mo = String(d.getMonth() + 1).padStart(2, '0')
  const day = String(d.getDate()).padStart(2, '0')
  return lang === 'fr' ? `${day}/${mo}/${y}` : `${y}-${mo}-${day}`
}

/**
 * formatPercent writes a share (0 to 1) as a percentage in lang, with one
 * decimal at most: "42,5 %" in French (decimal comma, a space before the
 * sign, as the French texts write it), "42.5%" in English. whole rounds
 * down to a whole number, for a percentile ("more than 97%").
 * @param {number} share
 * @param {string} lang
 * @param {boolean} [whole]
 */
export function formatPercent(share, lang, whole = false) {
  const x = Number(share) || 0
  // The epsilon keeps 0.29 at 29: 0.29 * 100 is 28.999999999999996.
  const n = whole ? Math.floor(x * 100 + 1e-9) : Math.round(x * 1000) / 10
  const s = String(n)
  return lang === 'fr' ? `${s.replace('.', ',')} %` : `${s}%`
}

/** decisionLabel names a decision in force in lang; "" for none. */
export function decisionLabel(decision, lang) {
  if (!decision) return ''
  switch (decision.action) {
    case 'fix':
      return translate(lang, 'decision.label.fix')
    case 'ignore':
      return translate(lang, 'decision.label.ignore')
    case 'defer':
      return translate(lang, 'decision.label.defer', { date: formatDate(decision.due_at, lang) })
    default:
      return ''
  }
}

/** maxJustification mirrors decide.MaxJustification, in characters. */
export const maxJustification = 1000

/** isoDay is the UTC calendar day of t plus days, as YYYY-MM-DD. */
export function isoDay(t, days = 0) {
  return new Date(t.getTime() + days * 24 * 3600 * 1000).toISOString().slice(0, 10)
}

/**
 * validateDecision checks a decision the way the server does (the decision
 * handler, then decide.Validate), so the page can say what is wrong before
 * sending: a known action; a date only to defer, written YYYY-MM-DD and after
 * now (the server reads it as midnight UTC, so today is already too early);
 * at most 1000 characters of justification; a justification to ignore. No
 * date to defer is fine: the server then defers by 30 days.
 * @returns {{ok: boolean, errorKey: string}}
 */
export function validateDecision({ action, why, until }, now) {
  const fail = (errorKey) => ({ ok: false, errorKey })
  const a = String(action || '').trim().toLowerCase()
  if (!['fix', 'defer', 'ignore'].includes(a)) return fail('decision.action_unknown')
  const u = String(until || '').trim()
  if (u !== '') {
    if (a !== 'defer') return fail('decision.until_not_defer')
    if (!/^\d{4}-\d{2}-\d{2}$/.test(u)) return fail('decision.until_invalid')
    const t = new Date(`${u}T00:00:00Z`)
    if (Number.isNaN(t.getTime()) || t.toISOString().slice(0, 10) !== u) return fail('decision.until_invalid')
    if (t.getTime() <= now.getTime()) return fail('decision.until_past')
  }
  const w = String(why || '').trim()
  if ([...w].length > maxJustification) return fail('decision.why_too_long')
  if (a === 'ignore' && w === '') return fail('decision.why_required')
  return { ok: true, errorKey: '' }
}
