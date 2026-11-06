import { describe, expect, test } from 'vitest'
import { reconstructedNote, series, severityNote, summaryText } from './openCurveView.js'

process.env.TZ = 'Europe/Paris'

const zeros = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }

/** day builds one point of GET /stats/open. */
function day(date, open, reconstructed = false) {
  return { date, open: { ...zeros, ...open }, reconstructed }
}

const days = [
  day('2026-10-30', { critical: 1, high: 2 }, true),
  day('2026-10-31', { critical: 1, high: 3, low: 1 }, true),
  day('2026-11-01', { high: 1 }),
  day('2026-11-02', { high: 1, medium: 4, unknown: 1 }),
]

describe('series: the stack', () => {
  test('each band starts where the one under it ends, and the top is the total of the day', () => {
    const s = series(days)
    expect(s.stack.map((p) => p.total)).toEqual([3, 5, 1, 6])
    for (const p of s.stack) {
      let under = 0
      for (const sev of ['critical', 'high', 'medium', 'low', 'unknown']) {
        expect(p.bands[sev][0]).toBe(under)
        under += p.open[sev]
        expect(p.bands[sev][1]).toBe(under)
      }
      expect(under).toBe(p.total)
    }
  })
  test('one area per severity that has a flaw on some day, most severe first; the top of the chart is the highest total', () => {
    const s = series(days)
    expect(s.paths.map((p) => p.severity)).toEqual(['critical', 'high', 'medium', 'low', 'unknown'])
    expect(series([day('2026-11-01', { high: 2 })]).paths.map((p) => p.severity)).toEqual(['high'])
    expect(s.max).toBe(6)
    for (const p of s.paths) expect(p.area).toMatch(/^M[\d. L]+Z$/)
  })
  test('the line on top of the last band reaches the top of the chart on the highest day', () => {
    const s = series(days, { width: 300, height: 100 })
    const top = s.paths[s.paths.length - 1].line
    expect(top.startsWith('M')).toBe(true)
    expect(top).toContain('300 0')
  })
  test('a lone day spreads over the whole width', () => {
    const s = series([day('2026-11-01', { high: 2 })], { width: 300, height: 100 })
    expect(s.paths[0].line).toBe('M0 0 L300 0')
  })
})

describe('series: the reconstructed part', () => {
  test('is drawn apart (dashed), up to the last reconstructed day, and joins the rest there', () => {
    const s = series(days, { width: 300, height: 100 })
    expect(s.reconstructedUntil).toBe('2026-10-31')
    expect(s.since).toBe('2026-11-01')
    expect(s.reconstructedX).toBe(100)
    const high = s.paths.find((p) => p.severity === 'high')
    // Days 0 and 1 dashed, days 1 to 3 solid: they share day 1.
    const pts = (d) => d.slice(1).split(' L')
    expect(pts(high.lineReconstructed)).toEqual(['0 50', '100 33.33'])
    expect(pts(high.line)).toHaveLength(3)
    expect(pts(high.line)[0]).toBe(pts(high.lineReconstructed)[1])
    expect(high.areaReconstructed).toMatch(/Z$/)
  })
  test('none reconstructed: no dashed part', () => {
    const s = series(days.slice(2))
    expect(s.reconstructedUntil).toBe(null)
    expect(s.paths.every((p) => p.lineReconstructed === '' && p.areaReconstructed === '')).toBe(true)
  })
  test('all reconstructed: no solid part', () => {
    const s = series(days.slice(0, 2))
    expect(s.reconstructedUntil).toBe('2026-10-31')
    expect(s.paths.every((p) => p.line === '' && p.area === '')).toBe(true)
  })
  test('the sentence says it, with the day as JJ/MM', () => {
    expect(reconstructedNote(series(days), 'fr')).toBe('Avant le 01/11, Michel ne gardait que le dernier changement de chaque faille : la partie en pointillés en est déduite, elle peut être un peu fausse.')
    expect(reconstructedNote(series(days), 'en')).toBe('Before 11-01, Michel only kept the last change of each flaw: the dashed part is worked out from it and may be a little off.')
    expect(reconstructedNote(series(days.slice(2)), 'fr')).toBe('')
  })
})

describe('series: the summary', () => {
  test('start, end, highest and lowest as numbers, with their day (the latest when tied)', () => {
    expect(series(days).summary).toEqual({ start: 3, end: 6, highest: 6, lowest: 1, startDate: '2026-10-30', endDate: '2026-11-02', highestDate: '2026-11-02', lowestDate: '2026-11-01' })
    expect(series([day('2026-11-01', { low: 2 }), day('2026-11-02', { low: 2 })]).summary.highestDate).toBe('2026-11-02')
  })
  test('the equivalent text says them in words', () => {
    expect(summaryText(series(days), 'fr')).toBe('Le 30/10/2026, 3 failles ouvertes. Le 02/11/2026, 6 failles ouvertes. Au plus haut : 6, le 02/11/2026. Au plus bas : 1, le 01/11/2026.')
    expect(summaryText(series(days), 'en')).toBe('On 2026-10-30, 3 open flaws. On 2026-11-02, 6 open flaws. Highest: 6, on 2026-11-02. Lowest: 1, on 2026-11-01.')
    expect(summaryText(series([day('2026-11-02', { low: 1 })]), 'fr')).toContain('Le 02/11/2026, 1 faille ouverte.')
  })
  test('an empty list gives no path and says there is no data', () => {
    const s = series([])
    expect(s.paths).toEqual([])
    expect(s.summary).toBe(null)
    expect(summaryText(s, 'fr')).toBe("Aucune donnée pour l'instant : Michel n'a encore rien compté.")
    expect(summaryText(s, 'en')).toBe('No data yet: Michel has not counted anything so far.')
  })
  test('the severity note says the severity of today is used', () => {
    expect(severityNote('fr')).toBe("Chaque faille compte avec sa gravité d'aujourd'hui, même pour les jours passés.")
    expect(severityNote('en')).toBe('Each flaw counts with its severity of today, even on past days.')
  })
})

describe('series: what cannot be read', () => {
  test('is null, never a curve at 0', () => {
    expect(series(null)).toBe(null)
    expect(series({ days: [] })).toBe(null)
    expect(series([{ date: '2026-11-01', open: { ...zeros, high: '2' } }])).toBe(null)
    expect(series([{ date: '2026-11-01', open: { ...zeros, high: -1 } }])).toBe(null)
    expect(series([{ date: 'x', open: zeros }])).toBe(null)
    expect(series([{ date: '2026-11-01' }])).toBe(null)
    expect(summaryText(null, 'fr')).toBe('')
  })
  test('a severity missing from a day counts 0, as the API gives every one', () => {
    expect(series([{ date: '2026-11-01', open: { high: 2 } }]).stack[0].total).toBe(2)
  })
})
