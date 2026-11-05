// Pure functions behind the Findings page (#/findings): the open findings of
// every project in one table, their filters kept in the address, and the
// reading of the lists the overview shares. No DOM, no fetch, no storage.
// Vitest covers them (findingsView.test.js).
import { translate } from '../i18n/index.js'
import { localDay, severities, severityOf, severityRank } from './digestView.js'
import { fixHash } from './fixView.js'
import { findingName } from './todoView.js'

/** The states a row can show, in the order of the filter. */
export const findingStates = ['new', 'pending', 'fix', 'defer', 'ignore', 'decided']

/**
 * The signals a row can carry, in the order of the chips: exploited right
 * now (KEV), likely to be exploited (EPSS percentile 0.9 or more), a
 * malicious component, a fixed version exists, no fixed version yet.
 */
export const signals = ['exploited', 'likely', 'malicious', 'fix', 'nofix']

/** likelyPercentile is the EPSS percentile from which a flaw is « likely to be exploited ». */
export const likelyPercentile = 0.9

/** The filters of the page, in the order the address writes them. */
const filterKeys = ['project', 'severity', 'status', 'signal', 'q']

/** emptyFilters is the page with nothing chosen. */
export function emptyFilters() {
  return { project: '', severity: '', status: '', signal: '', q: '' }
}

/** dec decodes a part of the address, '' when it is not valid. */
function dec(s) {
  try {
    return decodeURIComponent(String(s || '').replace(/\+/g, ' '))
  } catch {
    return ''
  }
}

/**
 * findingsRoute reads the filters of #/findings?project=…&severity=…&status=…&signal=…&q=….
 * A value the page does not know (a severity, a state, a signal) is dropped;
 * project and q are kept as written. null for another address.
 * @param {string} hash
 * @returns {{project: string, severity: string, status: string, signal: string, q: string}|null}
 */
export function findingsRoute(hash) {
  const m = String(hash || '').match(/^#\/findings(?:\?([^#]*))?$/)
  if (!m) return null
  const out = emptyFilters()
  for (const part of (m[1] || '').split('&')) {
    if (!part) continue
    const eq = part.indexOf('=')
    const key = eq < 0 ? part : part.slice(0, eq)
    const value = eq < 0 ? '' : dec(part.slice(eq + 1))
    if (!filterKeys.includes(key)) continue
    out[key] = value
  }
  if (!severities.includes(out.severity)) out.severity = ''
  if (!findingStates.includes(out.status)) out.status = ''
  if (!signals.includes(out.signal)) out.signal = ''
  out.q = out.q.trim()
  return out
}

/**
 * findingsHash writes the filters into the address, in a fixed order, only
 * those chosen: findingsRoute(findingsHash(f)) gives f back.
 * @param {Partial<{project: string, severity: string, status: string, signal: string, q: string}>} [filters]
 * @returns {string}
 */
export function findingsHash(filters = {}) {
  const parts = []
  for (const key of filterKeys) {
    const v = String(filters[key] ?? '').trim()
    if (v) parts.push(`${key}=${encodeURIComponent(v)}`)
  }
  return parts.length ? `#/findings?${parts.join('&')}` : '#/findings'
}

/**
 * stateOf is the state a row shows: new, pending (seen again), the decision
 * in force (fix, defer, ignore), decided (a decision the list does not
 * carry), gone.
 * @param {object} f FindingView
 */
export function stateOf(f) {
  if (f?.status === 'new' || f?.status === 'pending' || f?.status === 'gone') return f.status
  if (f?.status === 'decided') {
    const a = f.decision?.action
    return a === 'fix' || a === 'defer' || a === 'ignore' ? a : 'decided'
  }
  return 'pending'
}

/**
 * isListedOpen says whether a finding counts as open, as the digest counts
 * it: not gone, and not ignored. A deferred flaw is still open.
 * @param {object} f FindingView
 */
export function isListedOpen(f) {
  const s = stateOf(f)
  return s !== 'gone' && s !== 'ignore'
}

/** isDependency: a package's flaw, the only kind with a version that fixes it. */
function isDependency(f) {
  return !f.kind || f.kind === 'dependency'
}

/**
 * signalsOf lists the signals of a finding, in the order of signals. A
 * flaw found by a tool in the code has no version that fixes it: it carries
 * neither « fix » nor « nofix ».
 * @param {object} f FindingView
 * @returns {string[]}
 */
export function signalsOf(f) {
  const out = []
  if (!f) return out
  if (f.kev) out.push('exploited')
  if (Number(f.epss_percentile) >= likelyPercentile) out.push('likely')
  if (f.malicious) out.push('malicious')
  if (isDependency(f) && !f.malicious) {
    const fixed = Array.isArray(f.fixed_versions) ? f.fixed_versions.filter(Boolean) : []
    out.push(fixed.length ? 'fix' : 'nofix')
  }
  return out
}

/** title is a row's flaw in plain words: the package it touches, or the tool that found it. */
function title(f, lang) {
  const name = findingName(f) || ''
  if (!isDependency(f)) return translate(lang, 'todo.flaw_tool', { tool: name })
  return translate(lang, 'todo.flaw', { package: name })
}

/**
 * findingRows makes the rows of the table from the lists of the projects
 * ({name: FindingView[] | null}; null is a list not read, left out here and
 * named by unreadProjects). Only the open findings (isListedOpen) and the
 * ignored ones (for the « Ignorée » filter) are rows; the gone ones are not.
 * The most urgent first: exploited or malicious, then the most severe, then
 * the oldest seen.
 * @param {Record<string, object[]|null>} lists
 * @param {string} lang
 * @returns {object[]}
 */
export function findingRows(lists, lang) {
  const rows = []
  for (const [project, list] of Object.entries(lists || {})) {
    if (!Array.isArray(list)) continue
    for (const f of list) {
      if (!f || !f.id) continue
      const state = stateOf(f)
      if (state === 'gone') continue
      const fixed = Array.isArray(f.fixed_versions) ? f.fixed_versions.filter(Boolean) : []
      const cvss = typeof f.cvss === 'number' && f.cvss > 0 ? f.cvss : null
      const t = title(f, lang)
      rows.push({
        id: f.id,
        project: f.project || project,
        severity: severityOf(f.severity),
        title: t,
        installed: f.installed_version || '',
        fixed: fixed[0] || '',
        firstSeen: f.first_seen_at || '',
        seen: localDay(f.first_seen_at, lang),
        state,
        signals: signalsOf(f),
        hot: !!(f.kev || f.malicious),
        href: fixHash({ finding: f.id }),
        osvId: f.osv_id || f.rule_id || '',
        cvss,
        haystack: [t, f.package, f.project || project, f.osv_id, f.rule_id, f.source_key, ...(Array.isArray(f.aliases) ? f.aliases : [])]
          .filter(Boolean).join(' ').toLowerCase(),
      })
    }
  }
  const time = (s) => {
    const n = Date.parse(s)
    return Number.isNaN(n) ? Infinity : n
  }
  return rows.sort((a, b) => Number(b.hot) - Number(a.hot)
    || severityRank(a.severity) - severityRank(b.severity)
    || time(a.firstSeen) - time(b.firstSeen)
    || a.project.localeCompare(b.project)
    || a.id.localeCompare(b.id))
}

/**
 * filterRows keeps the rows that match every filter chosen. Without a state
 * chosen the ignored flaws stay out, as they stay out of the open count;
 * the « Ignorée » state shows them. q matches the flaw's words, its package,
 * its project and its identifiers, whatever the case.
 * @param {object[]} rows findingRows
 * @param {{project?: string, severity?: string, status?: string, signal?: string, q?: string}} filters
 */
export function filterRows(rows, filters = {}) {
  const words = String(filters.q || '').toLowerCase().split(/\s+/).filter(Boolean)
  return (rows || []).filter((r) => {
    if (filters.project && r.project !== filters.project) return false
    if (filters.severity && r.severity !== filters.severity) return false
    if (filters.status ? r.state !== filters.status : r.state === 'ignore') return false
    if (filters.signal && !r.signals.includes(filters.signal)) return false
    return words.every((w) => r.haystack.includes(w))
  })
}

/** projectChoices are the projects the filter offers: every project listed, by name. */
export function projectChoices(projects) {
  return [...new Set((projects || []).map((p) => p?.name).filter(Boolean))].sort((a, b) => a.localeCompare(b))
}

/**
 * unreadProjects names the projects whose list could not be read.
 * @param {Record<string, object[]|null>} lists
 * @returns {string[]}
 */
export function unreadProjects(lists) {
  return Object.entries(lists || {}).filter(([, l]) => !Array.isArray(l)).map(([name]) => name).sort((a, b) => a.localeCompare(b))
}

/**
 * readAllFindings reads the findings of every project: GET /projects, then
 * GET /projects/{name}/findings for each, unless known already holds the
 * project's list or the project counts no finding at all (total 0). read(path) resolves to the answer, or null when it could
 * not be read. It resolves to {projects, lists}: projects is null when the
 * projects could not be read; lists[name] is null for a list not read.
 * @param {(path: string) => Promise<any>} read
 * @param {string} lang
 * @param {{projects?: object[]|null, known?: Record<string, object[]|null>}} [given]
 * @returns {Promise<{projects: object[]|null, lists: Record<string, object[]|null>}>}
 */
export async function readAllFindings(read, lang, given = {}) {
  const q = `lang=${encodeURIComponent(lang)}`
  const projects = given.projects !== undefined ? given.projects : await read(`/projects?${q}`)
  if (!Array.isArray(projects)) return { projects: null, lists: {} }
  const names = projectChoices(projects)
  const known = given.known || {}
  const empty = new Set(projects.filter((p) => p && p.total === 0).map((p) => p.name))
  const answers = await Promise.all(names.map((name) => {
    if (Array.isArray(known[name])) return known[name]
    if (empty.has(name)) return []
    return read(`/projects/${encodeURIComponent(name)}/findings?${q}`)
  }))
  const lists = {}
  names.forEach((name, i) => {
    lists[name] = Array.isArray(answers[i]) ? answers[i] : null
  })
  return { projects, lists }
}
