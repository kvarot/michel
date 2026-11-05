import { describe, expect, test } from 'vitest'
import {
  ageCounts, ageOf, allListed, barHeight, openBySeverity, parkSummary, proposedCount, provenFixedCount,
  severityShares, signalCounts, weekKey, weekStart, weeklyChanges, weeklyMax,
} from './overviewView.js'

// The weeks are the person's: the tests run on a clock with a summer time.
process.env.TZ = 'Europe/Paris'

const zeros = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }

describe('openBySeverity', () => {
  test('sums every project, zeros kept', () => {
    const digest = { projects: [
      { name: 'shop', open: { ...zeros, critical: 1, medium: 2 } },
      { name: 'blog', open: { ...zeros } },
    ] }
    expect(openBySeverity(digest)).toEqual({ total: 3, bySeverity: { ...zeros, critical: 1, medium: 2 } })
    expect(openBySeverity({ projects: [] })).toEqual({ total: 0, bySeverity: zeros })
  })
  test('a severity the page does not know counts as unknown', () => {
    expect(openBySeverity({ projects: [{ name: 'demo', open: { odd: 2, high: 1 } }] }).bySeverity).toEqual({ ...zeros, high: 1, unknown: 2 })
  })
  test('is null, never 0, when it cannot be read', () => {
    expect(openBySeverity(null)).toBe(null)
    expect(openBySeverity({ projects: 'x' })).toBe(null)
    expect(openBySeverity({ projects: [{ name: 'shop' }] })).toBe(null)
    expect(openBySeverity({ projects: [{ name: 'shop', open: { high: '2' } }] })).toBe(null)
    expect(openBySeverity({ projects: [{ name: 'shop', open: { high: 1.5 } }] })).toBe(null)
  })
  test('severityShares keeps the severities with a count, most severe first', () => {
    const open = { total: 4, bySeverity: { ...zeros, low: 1, critical: 3 } }
    expect(severityShares(open)).toEqual([{ severity: 'critical', n: 3, share: 0.75 }, { severity: 'low', n: 1, share: 0.25 }])
    expect(severityShares({ total: 0, bySeverity: zeros })).toEqual([])
    expect(severityShares(null)).toEqual([])
  })
})

describe('the fixes', () => {
  const now = new Date('2026-11-05T12:00:00Z')
  const attempts = [
    { id: 'a', state: 'proposed', updated_at: '2026-11-01T00:00:00Z' },
    { id: 'b', state: 'proposed' },
    { id: 'c', state: 'proven_fixed', updated_at: '2026-11-04T10:00:00Z' },
    { id: 'd', state: 'proven_fixed', updated_at: '2026-10-06T12:00:00Z' },
    { id: 'e', state: 'proven_fixed', updated_at: '2026-10-06T11:59:59Z' },
    { id: 'f', state: 'proven_fixed', updated_at: 'not a time' },
    { id: 'g', state: 'applied', updated_at: '2026-11-04T10:00:00Z' },
    null,
  ]
  test('proposedCount counts what waits for approval', () => {
    expect(proposedCount(attempts)).toBe(2)
    expect(proposedCount([])).toBe(0)
    expect(proposedCount(null)).toBe(null)
  })
  test('provenFixedCount counts the proven fixes of the last 30 days, the edge included', () => {
    expect(provenFixedCount(attempts, now)).toBe(2)
    expect(provenFixedCount([], now)).toBe(0)
    expect(provenFixedCount(null, now)).toBe(null)
  })
})

describe('parkSummary', () => {
  test('counts the projects, the active servers and the failed checks', () => {
    const projects = [{ name: 'shop', last_scan_status: 'failed' }, { name: 'blog', last_scan_status: 'done' }, { name: 'demo', last_scan_status: 'interrupted' }]
    const servers = [{ id: '1', active: true, state: { code: 'check_failed' } }, { id: '2', active: true, state: { code: 'clean' } }, { id: '3', active: false, state: { code: 'check_failed' } }]
    expect(parkSummary(projects, servers)).toEqual({ projects: 3, servers: 2, failed: 3 })
    expect(parkSummary([], [])).toEqual({ projects: 0, servers: 0, failed: 0 })
  })
  test('what cannot be read is null, and so is the failed count it would hide', () => {
    expect(parkSummary(null, [])).toEqual({ projects: null, servers: 0, failed: null })
    expect(parkSummary([], null)).toEqual({ projects: 0, servers: null, failed: null })
  })
})

describe('weeks', () => {
  test('weekStart is the local Monday at midnight', () => {
    const m = weekStart(new Date(2026, 10, 5, 15, 0))
    expect([m.getFullYear(), m.getMonth(), m.getDate(), m.getHours(), m.getDay()]).toEqual([2026, 10, 2, 0, 1])
    expect(weekKey(new Date(2026, 10, 2, 0, 0))).toBe('2026-11-02')
    expect(weekKey(new Date(2026, 10, 8, 23, 59))).toBe('2026-11-02')
    expect(weekKey(new Date(2026, 10, 9, 0, 0))).toBe('2026-11-09')
  })
  test('a change of hour does not move the weeks', () => {
    // 25 October 2026: Paris goes back from UTC+2 to UTC+1.
    expect(weekKey(new Date('2026-10-25T22:30:00Z'))).toBe('2026-10-19')
    expect(weekKey(new Date('2026-10-25T23:30:00Z'))).toBe('2026-10-26')
    // 29 March 2026: Paris goes forward from UTC+1 to UTC+2.
    expect(weekKey(new Date('2026-03-29T21:30:00Z'))).toBe('2026-03-23')
    expect(weekKey(new Date('2026-03-29T22:30:00Z'))).toBe('2026-03-30')
  })
  test('weeklyChanges sums the digests of each week, the local week of their until', () => {
    const now = new Date('2026-10-28T11:00:00Z')
    const runs = [
      { until: '2026-10-25T23:30:00Z', projects: [{ name: 'shop', new: 2, gone: 1 }, { name: 'blog', new: 0, gone: 0 }] },
      { until: '2026-10-27T06:00:00Z', projects: [{ name: 'shop', new: 1, gone: 0 }] },
      { until: '2026-10-25T22:30:00Z', projects: [{ name: 'shop', new: 0, gone: 4 }] },
      { until: '2026-09-01T06:00:00Z', projects: [{ name: 'shop', new: 9, gone: 9 }] },
      { until: 'nope', projects: [{ name: 'shop', new: 9, gone: 9 }] },
    ]
    const weeks = weeklyChanges(runs, now)
    expect(weeks.map((w) => w.key)).toEqual(['2026-09-07', '2026-09-14', '2026-09-21', '2026-09-28', '2026-10-05', '2026-10-12', '2026-10-19', '2026-10-26'])
    const last = weeks[7]
    expect([last.fresh, last.gone, last.sent, last.unread]).toEqual([3, 1, 2, false])
    expect([weeks[6].fresh, weeks[6].gone, weeks[6].sent]).toEqual([0, 4, 1])
  })
  test('a week with no digest is not read, never 0; a digest sent with zeros is 0', () => {
    const now = new Date('2026-11-05T12:00:00Z')
    const weeks = weeklyChanges([{ until: '2026-11-03T06:00:00Z', projects: [{ name: 'demo', new: 0, gone: 0 }] }], now)
    expect([weeks[7].fresh, weeks[7].gone, weeks[7].sent]).toEqual([0, 0, 1])
    expect([weeks[6].fresh, weeks[6].gone, weeks[6].sent]).toEqual([null, null, 0])
    expect(weeklyChanges([{ until: '2026-11-03T06:00:00Z', projects: [] }], now)[7].fresh).toBe(0)
  })
  test('a digest whose counts cannot be read makes its week not read', () => {
    const now = new Date('2026-11-05T12:00:00Z')
    const weeks = weeklyChanges([
      { until: '2026-11-03T06:00:00Z', projects: [{ name: 'shop', new: 1, gone: 0 }] },
      { until: '2026-11-04T06:00:00Z', projects: [{ name: 'shop', new: 'x', gone: 0 }] },
      { until: '2026-11-05T06:00:00Z', projects: null },
    ], now)
    expect([weeks[7].fresh, weeks[7].gone, weeks[7].sent, weeks[7].unread]).toEqual([null, null, 3, true])
  })
  test('the weeks cross a year', () => {
    const now = new Date('2027-01-06T12:00:00Z')
    const weeks = weeklyChanges([
      { until: '2026-12-31T23:30:00Z', projects: [{ name: 'shop', new: 1, gone: 0 }] },
      { until: '2027-01-03T23:30:00Z', projects: [{ name: 'shop', new: 0, gone: 2 }] },
    ], now)
    expect(weeks.slice(-3).map((w) => [w.key, w.fresh, w.gone])).toEqual([
      ['2026-12-21', null, null],
      ['2026-12-28', 1, 0],
      ['2027-01-04', 0, 2],
    ])
  })
  test('the digests cannot be read: null', () => {
    expect(weeklyChanges(null, new Date())).toBe(null)
  })
  test('weeklyMax and barHeight', () => {
    expect(weeklyMax([{ fresh: 3, gone: null }, { fresh: null, gone: 5 }])).toBe(5)
    expect(weeklyMax([{ fresh: null, gone: null }])).toBe(0)
    expect(barHeight(null, 5, 80)).toBe(0)
    expect(barHeight(0, 5, 80)).toBe(0)
    expect(barHeight(5, 5, 80)).toBe(80)
    expect(barHeight(1, 1000, 80)).toBe(2)
  })
})

describe('ages', () => {
  const now = new Date('2026-11-05T12:00:00Z')
  const ago = (days, extraMs = 0) => new Date(now.getTime() - days * 86400000 - extraMs).toISOString()
  test('ageOf counts whole days', () => {
    expect(ageOf(ago(0), now)).toBe(0)
    expect(ageOf(ago(30, 1), now)).toBe(30)
    expect(ageOf(ago(31), now)).toBe(31)
    expect(ageOf('2026-12-01T00:00:00Z', now)).toBe(0)
    expect(ageOf('', now)).toBe(null)
    expect(ageOf('yesterday', now)).toBe(null)
  })
  test('the buckets hold their edges', () => {
    const f = (days, status = 'new', decision = null) => ({ id: String(days), status, decision, first_seen_at: ago(days) })
    const findings = [f(0), f(30), f(31), f(90), f(91), f(180), f(181), f(900),
      f(5, 'decided', { action: 'ignore' }), f(5, 'gone'), f(5, 'decided', { action: 'defer' }),
      { id: 'x', status: 'pending', first_seen_at: 'later' }]
    expect(ageCounts(findings, now)).toEqual({
      buckets: [{ key: 'd0_30', n: 3 }, { key: 'd31_90', n: 2 }, { key: 'd91_180', n: 2 }, { key: 'd181', n: 2 }],
      unknown: 1,
      total: 10,
    })
  })
  test('nothing open: zeros, since every list was read', () => {
    expect(ageCounts([], now)).toEqual({ buckets: [{ key: 'd0_30', n: 0 }, { key: 'd31_90', n: 0 }, { key: 'd91_180', n: 0 }, { key: 'd181', n: 0 }], unknown: 0, total: 0 })
  })
})

describe('signals', () => {
  test('signalCounts counts the open flaws of each signal, zeros kept', () => {
    const findings = [
      { id: '1', status: 'new', kev: true, epss_percentile: 0.95, fixed_versions: ['2.0.0'] },
      { id: '2', status: 'pending', epss_percentile: 0.9, fixed_versions: [] },
      { id: '3', status: 'new', malicious: true, fixed_versions: [] },
      { id: '4', status: 'new', kind: 'code', fixed_versions: [] },
      { id: '5', status: 'gone', kev: true },
      { id: '6', status: 'decided', decision: { action: 'ignore' }, kev: true },
      { id: '7', status: 'new', epss_percentile: 0.89 },
    ]
    expect(signalCounts(findings)).toEqual([
      { signal: 'exploited', n: 1 },
      { signal: 'likely', n: 2 },
      { signal: 'malicious', n: 1 },
      { signal: 'fix', n: 1 },
      { signal: 'nofix', n: 2 },
    ])
    expect(signalCounts([]).every((s) => s.n === 0)).toBe(true)
  })
  test('allListed keeps only the lists that were read', () => {
    expect(allListed({ shop: [{ id: '1' }], blog: null, demo: [] })).toEqual([{ id: '1' }])
    expect(allListed(null)).toEqual([])
  })
})
