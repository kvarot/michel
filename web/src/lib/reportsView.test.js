import { describe, expect, test } from 'vitest'
import { checkRows, oldestLine, period, projectRows, reportsHash, reportsRoute, severityRows, summary } from './reportsView.js'

// The days are the person's: the tests run on a clock with a summer time.
process.env.TZ = 'Europe/Paris'

/** zeros is a severity map at 0. */
const zeros = () => ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 })

/** report is an answer of GET /reports with every count at 0, then over. */
function report(over = {}) {
  return {
    from: '2026-10-26', to: '2026-11-01',
    found: zeros(), gone_by_michel: zeros(), gone_elsewhere: zeros(),
    decisions: { fix: 0, defer: 0, ignore: 0 },
    fixes: { proposed: 0, applied: 0, proven: 0 },
    open_start: zeros(), open_end: zeros(), oldest_open: null,
    checks: { projects: { done: 0, failed: 0 }, servers: { done: 0, failed: null } },
    servers: { found: 0, closed: 0 },
    projects: [],
    reconstructed: false,
    ...over,
  }
}

describe('period: weeks', () => {
  test('the week of 2026-11-04 runs Monday 2026-11-02 to Sunday 2026-11-08', () => {
    const p = period('week', '2026-11-04', '2026-11-20')
    expect([p.from, p.to]).toEqual(['2026-11-02', '2026-11-08'])
    expect(p.current).toBe(false)
    expect(p.prev).toBe('2026-10-26')
    expect(p.next).toBe('2026-11-09')
  })
  test('a Monday and a Sunday stay in their own week', () => {
    expect(period('week', '2026-11-02', '2026-11-20').from).toBe('2026-11-02')
    expect(period('week', '2026-11-08', '2026-11-20').from).toBe('2026-11-02')
  })
  test('the week of the change of hour still has seven days', () => {
    const p = period('week', '2026-10-25', '2026-11-20')
    expect([p.from, p.to]).toEqual(['2026-10-19', '2026-10-25'])
    expect(p.next).toBe('2026-10-26')
  })
  test('next is null in the current week, which is marked current', () => {
    const p = period('week', '2026-11-04', '2026-11-06')
    expect(p.current).toBe(true)
    expect(p.next).toBe(null)
    expect(p.prev).toBe('2026-10-26')
  })
  test('a day after the current week is never offered: the current week is shown', () => {
    const p = period('week', '2027-03-01', '2026-11-06')
    expect([p.from, p.to, p.current, p.next]).toEqual(['2026-11-02', '2026-11-08', true, null])
  })
  test('the default is the previous complete week', () => {
    for (const at of [undefined, '', 'nonsense', '2026-02-30']) {
      const p = period('week', at, '2026-11-06')
      expect([p.from, p.to, p.current, p.next], String(at)).toEqual(['2026-10-26', '2026-11-01', false, '2026-11-02'])
    }
    // On a Monday, the previous week ended yesterday.
    expect(period('week', '', '2026-11-02').from).toBe('2026-10-26')
    // An unknown kind is a week.
    expect(period('year', '', '2026-11-06').from).toBe('2026-10-26')
  })
  test('today may be a Date', () => {
    expect(period('week', '', new Date(2026, 10, 6, 23, 30)).from).toBe('2026-10-26')
  })
})

describe('period: months', () => {
  test('a month runs from the 1st to its last day', () => {
    const p = period('month', '2026-11-04', '2027-01-10')
    expect([p.from, p.to, p.prev, p.next, p.current]).toEqual(['2026-11-01', '2026-11-30', '2026-10-01', '2026-12-01', false])
  })
  test('February 2028 ends on the 29th, February 2027 on the 28th', () => {
    expect(period('month', '2028-02-10', '2028-06-01').to).toBe('2028-02-29')
    expect(period('month', '2027-02-10', '2028-06-01').to).toBe('2027-02-28')
  })
  test('January goes back to December of the year before', () => {
    expect(period('month', '2027-01-15', '2027-06-01').prev).toBe('2026-12-01')
  })
  test('next is null in the current month; with no day, the previous month', () => {
    const p = period('month', '2026-11-30', '2026-11-06')
    expect([p.current, p.next]).toEqual([true, null])
    const d = period('month', '', '2026-11-06')
    expect([d.from, d.to, d.next]).toEqual(['2026-10-01', '2026-10-31', '2026-11-01'])
  })
})

describe('period: labels', () => {
  test('a week and a month are named in each language', () => {
    expect(period('week', '2026-11-04', '2026-11-20', 'fr').label).toBe('Semaine du 02/11/2026 au 08/11/2026')
    expect(period('week', '2026-11-04', '2026-11-20', 'en').label).toBe('Week of 2026-11-02 to 2026-11-08')
    expect(period('month', '2026-11-04', '2027-01-10', 'fr').label).toBe('Novembre 2026')
    expect(period('month', '2026-11-04', '2027-01-10', 'en').label).toBe('November 2026')
  })
})

describe('the address', () => {
  test('reportsRoute reads the period and the day, and refuses other pages', () => {
    expect(reportsRoute('#/reports')).toEqual({ period: 'week', at: '' })
    expect(reportsRoute('#/reports?period=month&at=2026-10-01')).toEqual({ period: 'month', at: '2026-10-01' })
    expect(reportsRoute('#/reports?period=year&at=x')).toEqual({ period: 'week', at: 'x' })
    expect(reportsRoute('#/reportsx')).toBe(null)
    expect(reportsRoute('#/findings')).toBe(null)
  })
  test('reportsHash keeps the period and the day', () => {
    expect(reportsHash('month', '2026-10-01')).toBe('#/reports?period=month&at=2026-10-01')
    expect(reportsHash('week', '')).toBe('#/reports?period=week')
    expect(reportsRoute(reportsHash('week', '2026-11-02'))).toEqual({ period: 'week', at: '2026-11-02' })
  })
})

describe('summary', () => {
  const today = '2026-11-20'
  test('says the counts of a past week, plural for many', () => {
    const r = report({
      from: '2026-11-02', to: '2026-11-08',
      found: { ...zeros(), high: 3, low: 1 },
      gone_by_michel: { ...zeros(), critical: 2 },
      gone_elsewhere: { ...zeros(), medium: 4 },
      fixes: { proposed: 2, applied: 1, proven: 1 },
    })
    expect(summary(r, 'fr', today)).toBe('La semaine du 02/11/2026 au 08/11/2026 : 4 failles trouvées, 6 corrigées, 2 correctifs proposés à ta validation.')
    expect(summary(r, 'en', today)).toBe('The week of 2026-11-02 to 2026-11-08: 4 flaws found, 6 fixed, 2 fixes submitted for your approval.')
  })
  test('the current week and the current month say « this week » and « this month »', () => {
    const r = report({ from: '2026-11-16', to: '2026-11-22', found: { ...zeros(), high: 4 } })
    expect(summary(r, 'fr', today)).toBe('Cette semaine : 4 failles trouvées, 0 corrigée, 0 correctif proposé à ta validation.')
    const m = report({ from: '2026-11-01', to: '2026-11-30' })
    expect(summary(m, 'en', today)).toBe('This month: 0 flaws found, 0 fixed, 0 fixes submitted for your approval.')
    const past = report({ from: '2026-10-01', to: '2026-10-31' })
    expect(summary(past, 'fr', today)).toMatch(/^En octobre 2026 : /)
    expect(summary(past, 'en', today)).toMatch(/^In October 2026: /)
  })
  test('one of each is singular', () => {
    const r = report({ from: '2026-11-02', to: '2026-11-08', found: { ...zeros(), low: 1 }, gone_elsewhere: { ...zeros(), low: 1 }, fixes: { proposed: 1, applied: 0, proven: 0 } })
    expect(summary(r, 'fr', today)).toContain(': 1 faille trouvée, 1 corrigée, 1 correctif proposé à ta validation.')
    expect(summary(r, 'en', today)).toContain(': 1 flaw found, 1 fixed, 1 fix submitted for your approval.')
  })
  test('an empty period gives zeros, not « not read »', () => {
    const fr = summary(report(), 'fr', today)
    expect(fr).toContain('0 faille trouvée, 0 corrigée, 0 correctif proposé')
    expect(fr).not.toContain('non lu')
  })
  test('a count that cannot be read says « non lu », never 0', () => {
    const r = report({ from: '2026-11-02', to: '2026-11-08', found: null, gone_by_michel: { high: 'x' }, fixes: { proposed: null } })
    expect(summary(r, 'fr', today)).toBe('La semaine du 02/11/2026 au 08/11/2026 : failles trouvées : non lu, corrigées : non lu, correctifs proposés : non lu.')
    expect(summary(r, 'en', today)).toBe('The week of 2026-11-02 to 2026-11-08: flaws found: not read, fixed: not read, fixes submitted: not read.')
  })
  test('no report gives no sentence', () => {
    expect(summary(null, 'fr', today)).toBe('')
  })
})

describe('the tables', () => {
  test('severityRows gives one line per severity and the totals, null when unread', () => {
    const r = report({ found: { ...zeros(), critical: 2, low: 1 }, open_end: { ...zeros(), low: 5 }, gone_elsewhere: null })
    const rows = severityRows(r)
    expect(rows.map((x) => x.severity)).toEqual(['critical', 'high', 'medium', 'low', 'unknown', 'total'])
    expect(rows[0]).toEqual({ severity: 'critical', found: 2, goneByMichel: 0, goneElsewhere: null, openStart: 0, openEnd: 0 })
    expect(rows[5]).toEqual({ severity: 'total', found: 3, goneByMichel: 0, goneElsewhere: null, openStart: 0, openEnd: 5 })
  })
  test('checkRows says « not read » for the failed checks of the servers, never 0', () => {
    const rows = checkRows(report({ checks: { projects: { done: 4, failed: 1 }, servers: { done: 2, failed: null } } }))
    expect(rows).toEqual([{ key: 'projects', done: 4, failed: 1 }, { key: 'servers', done: 2, failed: null }])
    expect(checkRows(report({ checks: null }))).toEqual([{ key: 'projects', done: null, failed: null }, { key: 'servers', done: null, failed: null }])
  })
  test('projectRows keeps the counts, null when unread', () => {
    const r = report({ projects: [{ name: 'demo', found: 1, gone: 2, open_end: 3, decisions: 0 }, { name: 'shop', found: -1 }] })
    expect(projectRows(r)).toEqual([
      { name: 'demo', found: 1, gone: 2, openEnd: 3, decisions: 0 },
      { name: 'shop', found: null, gone: null, openEnd: null, decisions: null },
    ])
    expect(projectRows(report({ projects: null }))).toBe(null)
  })
  test('oldestLine names the flaw open the longest, with a link to its page', () => {
    const r = report({ oldest_open: { finding_id: 'f 1', package: 'lodash', osv_id: 'GHSA-1', first_seen_at: '2026-09-03T08:00:00Z' } })
    expect(oldestLine(r, 'fr')).toEqual({ name: 'lodash (GHSA-1)', since: '03/09/2026', href: '#/fix?finding=f%201' })
    expect(oldestLine(r, 'en').since).toBe('2026-09-03')
    expect(oldestLine(report(), 'fr')).toBe(null)
  })
})
