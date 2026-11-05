import { describe, expect, test } from 'vitest'
import {
  emptyFilters, filterRows, filtersFromHash, findingRows, knownFilters, findingsHash, findingsRoute, isListedOpen, projectChoices,
  readAllFindings, signalsOf, stateOf, unreadProjects,
} from './findingsView.js'

describe('the address', () => {
  test('findingsRoute reads every filter', () => {
    expect(findingsRoute('#/findings')).toEqual(emptyFilters())
    expect(findingsRoute('#/findings?')).toEqual(emptyFilters())
    expect(findingsRoute('#/findings?project=shop&severity=high&status=defer&signal=exploited&q=log%20in'))
      .toEqual({ project: 'shop', severity: 'high', status: 'defer', signal: 'exploited', q: 'log in' })
    expect(findingsRoute('#/findings?q=a+b')).toEqual({ ...emptyFilters(), q: 'a b' })
  })
  test('a value the page does not know is dropped, a broken one too', () => {
    expect(findingsRoute('#/findings?severity=huge&status=maybe&signal=loud&other=1&project=%E0'))
      .toEqual(emptyFilters())
  })
  test('another address is null', () => {
    expect(findingsRoute('#/')).toBe(null)
    expect(findingsRoute('#/findingsx')).toBe(null)
    expect(findingsRoute('#/fix?finding=a')).toBe(null)
  })
  test('filtersFromHash gives a new object each time, so the page follows the address', () => {
    const a = filtersFromHash('#/findings')
    const b = filtersFromHash('#/findings')
    expect(a).toEqual(emptyFilters())
    expect(a).not.toBe(b)
    expect(filtersFromHash('#/')).toEqual(emptyFilters())
    expect(filtersFromHash('#/findings?q=x').q).toBe('x')
  })
  test('knownFilters drops a project the list does not hold', () => {
    const f = { ...emptyFilters(), project: 'gone', q: 'x' }
    expect(knownFilters(f, ['shop', 'blog'])).toEqual({ ...emptyFilters(), q: 'x' })
    expect(knownFilters({ ...f, project: 'shop' }, ['shop'])).toEqual({ ...f, project: 'shop' })
    expect(knownFilters(f, null)).toBe(f)
    expect(knownFilters(emptyFilters(), [])).toEqual(emptyFilters())
  })
  test('findingsHash writes only what is chosen, in a fixed order', () => {
    expect(findingsHash()).toBe('#/findings')
    expect(findingsHash(emptyFilters())).toBe('#/findings')
    expect(findingsHash({ q: 'x', project: 'blog' })).toBe('#/findings?project=blog&q=x')
    expect(findingsHash({ signal: 'nofix', q: '  ' })).toBe('#/findings?signal=nofix')
  })
  test('the filters survive the round trip', () => {
    const cases = [
      { project: 'my shop', severity: 'critical', status: 'new', signal: 'likely', q: 'a&b=c #d %' },
      { ...emptyFilters(), project: 'démo/é' },
      { ...emptyFilters(), q: 'é?' },
      emptyFilters(),
    ]
    for (const f of cases) expect(findingsRoute(findingsHash(f))).toEqual(f)
  })
})

describe('states and signals', () => {
  test('stateOf names the state a row shows', () => {
    expect(stateOf({ status: 'new' })).toBe('new')
    expect(stateOf({ status: 'pending' })).toBe('pending')
    expect(stateOf({ status: 'gone' })).toBe('gone')
    expect(stateOf({ status: 'decided', decision: { action: 'fix' } })).toBe('fix')
    expect(stateOf({ status: 'decided', decision: { action: 'defer' } })).toBe('defer')
    expect(stateOf({ status: 'decided', decision: { action: 'ignore' } })).toBe('ignore')
    expect(stateOf({ status: 'decided', decision: null })).toBe('decided')
  })
  test('open is everything but the gone and the ignored', () => {
    expect(isListedOpen({ status: 'new' })).toBe(true)
    expect(isListedOpen({ status: 'decided', decision: { action: 'defer' } })).toBe(true)
    expect(isListedOpen({ status: 'decided', decision: { action: 'ignore' } })).toBe(false)
    expect(isListedOpen({ status: 'gone' })).toBe(false)
  })
  test('signalsOf', () => {
    expect(signalsOf({ kev: true, epss_percentile: 0.97, fixed_versions: ['1.2.3'] })).toEqual(['exploited', 'likely', 'fix'])
    expect(signalsOf({ fixed_versions: [] })).toEqual(['nofix'])
    expect(signalsOf({ fixed_versions: [''] })).toEqual(['nofix'])
    expect(signalsOf({})).toEqual(['nofix'])
    expect(signalsOf({ malicious: true, fixed_versions: [] })).toEqual(['malicious'])
    expect(signalsOf({ kind: 'code', epss_percentile: 0.9 })).toEqual(['likely'])
    expect(signalsOf(null)).toEqual([])
  })
})

const lists = {
  shop: [
    { id: 'f1', project: 'shop', package: 'acme/http', osv_id: 'GHSA-aaaa-bbbb-cccc', severity: 'medium', status: 'new', installed_version: '1.0.0', fixed_versions: ['1.0.4', '2.0.0'], first_seen_at: '2026-10-01T10:00:00Z', cvss: 5.3 },
    { id: 'f2', project: 'shop', package: 'acme/log', osv_id: 'CVE-2026-0001', aliases: ['GHSA-zzzz-yyyy-xxxx'], severity: 'low', status: 'decided', decision: { action: 'ignore' }, first_seen_at: '2026-09-01T10:00:00Z' },
    { id: 'f3', project: 'shop', package: 'acme/old', severity: 'critical', status: 'gone' },
  ],
  blog: [
    { id: 'f4', project: 'blog', package: 'acme/mail', severity: 'weird', status: 'pending', kev: true, first_seen_at: '2026-11-01T10:00:00Z', cvss: 0 },
    { id: 'f5', project: 'blog', kind: 'code', source_key: 'plugin.lint', rule_id: 'R1', severity: 'high', status: 'decided', decision: { action: 'defer' }, first_seen_at: '2026-08-01T10:00:00Z' },
  ],
  demo: null,
}

describe('findingRows', () => {
  const rows = findingRows(lists, 'fr')
  test('one row per finding not gone, the most urgent first', () => {
    expect(rows.map((r) => r.id)).toEqual(['f4', 'f5', 'f1', 'f2'])
  })
  test('a row says the flaw in words and leads to its page', () => {
    const r = rows.find((x) => x.id === 'f1')
    expect(r).toMatchObject({ project: 'shop', severity: 'medium', title: 'Une faille touche acme/http', installed: '1.0.0', fixed: '1.0.4', state: 'new', signals: ['fix'], href: '#/fix?finding=f1', osvId: 'GHSA-aaaa-bbbb-cccc', cvss: 5.3 })
    expect(r.seen).toMatch(/^0?1\/10\/2026$/)
    expect(rows.find((x) => x.id === 'f5').title).toBe('Une faille dans ton projet, trouvée par lint')
    expect(rows.find((x) => x.id === 'f5').signals).toEqual([])
  })
  test('an unknown severity is said unknown, a missing score is null', () => {
    const r = rows.find((x) => x.id === 'f4')
    expect(r.severity).toBe('unknown')
    expect(r.cvss).toBe(null)
    expect(r.hot).toBe(true)
  })
  test('unreadProjects names the lists not read', () => {
    expect(unreadProjects(lists)).toEqual(['demo'])
    expect(unreadProjects({})).toEqual([])
  })
})

describe('filterRows', () => {
  const rows = findingRows(lists, 'en')
  const ids = (f) => filterRows(rows, f).map((r) => r.id)
  test('nothing chosen: every open flaw, the ignored ones left out', () => {
    expect(ids({})).toEqual(['f4', 'f5', 'f1'])
    expect(ids(emptyFilters())).toEqual(['f4', 'f5', 'f1'])
  })
  test('each filter alone', () => {
    expect(ids({ project: 'shop' })).toEqual(['f1'])
    expect(ids({ severity: 'unknown' })).toEqual(['f4'])
    expect(ids({ status: 'ignore' })).toEqual(['f2'])
    expect(ids({ status: 'defer' })).toEqual(['f5'])
    expect(ids({ signal: 'exploited' })).toEqual(['f4'])
    expect(ids({ signal: 'nofix' })).toEqual(['f4'])
    expect(ids({ q: 'HTTP' })).toEqual(['f1'])
    expect(ids({ q: 'ghsa-zzzz' })).toEqual([])
  })
  test('filters combine', () => {
    expect(ids({ project: 'shop', status: 'ignore', q: 'ghsa-zzzz' })).toEqual(['f2'])
    expect(ids({ project: 'blog', severity: 'high' })).toEqual(['f5'])
    expect(ids({ project: 'blog', signal: 'fix' })).toEqual([])
    expect(ids({ q: 'acme blog' })).toEqual(['f4'])
  })
})

describe('reading', () => {
  test('projectChoices', () => {
    expect(projectChoices([{ name: 'shop' }, { name: 'blog' }, null, { name: 'shop' }])).toEqual(['blog', 'shop'])
    expect(projectChoices(null)).toEqual([])
  })
  test('readAllFindings reads each list once, keeps what is known, skips an empty project, says what failed', async () => {
    const asked = []
    const read = async (path) => {
      asked.push(path)
      if (path.startsWith('/projects?')) return [{ name: 'shop', total: 2 }, { name: 'blog', total: 1 }, { name: 'demo', total: 0 }, { name: 'my site', total: 3 }]
      if (path.startsWith('/projects/blog/')) return null
      return [{ id: 'x' }]
    }
    const got = await readAllFindings(read, 'fr', { known: { shop: [{ id: 'k' }] } })
    expect(asked).toEqual(['/projects?lang=fr', '/projects/blog/findings?lang=fr', '/projects/my%20site/findings?lang=fr'])
    expect(got.lists).toEqual({ blog: null, demo: [], 'my site': [{ id: 'x' }], shop: [{ id: 'k' }] })
  })
  test('the projects cannot be read', async () => {
    expect(await readAllFindings(async () => null, 'en')).toEqual({ projects: null, lists: {} })
    expect(await readAllFindings(async () => [], 'en', { projects: null })).toEqual({ projects: null, lists: {} })
  })
})
