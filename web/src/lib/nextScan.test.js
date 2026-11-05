import { describe, expect, test } from 'vitest'
import { nextScanText, withScanState } from './projectsView.js'

const card = import.meta.glob('../components/ProjectCard.vue', { query: '?raw', import: 'default', eager: true })

// Dates in the local zone of the test machine, as the page reads them.
const now = new Date(2026, 10, 5, 9, 0)
const iso = (d) => d.toISOString()

describe('nextScanText', () => {
  test('tomorrow, today, a later day', () => {
    expect(nextScanText({ auto_scan: true, next_scan_at: iso(new Date(2026, 10, 6, 7, 0)) }, 'fr', now)).toBe('Prochain contrôle : demain à 07:00')
    expect(nextScanText({ auto_scan: true, next_scan_at: iso(new Date(2026, 10, 5, 7, 0)) }, 'fr', now)).toBe("Prochain contrôle : aujourd'hui à 07:00")
    expect(nextScanText({ auto_scan: true, next_scan_at: iso(new Date(2026, 10, 6, 7, 0)) }, 'en', now)).toBe('Next check: tomorrow at 07:00')
    expect(nextScanText({ auto_scan: true, next_scan_at: iso(new Date(2026, 10, 9, 6, 5)) }, 'en', now)).toMatch(/^Next check: .+ at 06:05$/)
  })
  test('the watch is off for the project, or for all', () => {
    expect(nextScanText({ auto_scan: false, next_scan_at: '' }, 'fr', now)).toBe('Veille coupée pour ce projet')
    expect(nextScanText({ auto_scan: true, next_scan_at: '' }, 'fr', now)).toBe('Veille du jour coupée : Michel ne contrôle ce projet que quand tu le demandes')
  })
  test('nothing before the page has read the projects', () => {
    expect(nextScanText({}, 'fr', now)).toBe('')
  })
  test('the view carries the watch to the card', () => {
    const p = withScanState({ name: 'demo' }, { auto_scan: false, next_scan_at: '' })
    expect(p.auto_scan).toBe(false)
    expect(p.next_scan_at).toBe('')
  })
  test('the card shows it', () => {
    const src = Object.values(card)[0]
    expect(src).toContain('nextScanText(')
  })
})
