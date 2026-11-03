import { describe, expect, test } from 'vitest'
import fr from './fr.json'

// Families of texts a novice reads in simple mode.
const families = ['nav.', 'todo.', 'resolved.', 'path.', 'plan.', 'expo.', 'guide.', 'empty.', 'help.']
// Keys allowed to use port, paquet or SSH because their own sentence explains it.
// Empty for now: a task that adds one lists it here, in the same commit.
const jargonExceptions = []

const simpleEntries = Object.entries(fr).filter(([k]) => families.some((f) => k.startsWith(f)))

describe('no unexplained jargon in simple texts', () => {
  test('no unexplained jargon in simple texts', () => {
    const bad = []
    for (const [k, v] of simpleEntries) {
      if (/\b(CVE|CVSS|GHSA|EPSS|KEV)\b/.test(v)) bad.push(`${k}: identifier word`)
      if (/\b(port|paquet|SSH)\b/i.test(v) && !jargonExceptions.includes(k)) bad.push(`${k}: port, paquet or SSH`)
    }
    expect(bad).toEqual([])
  })
  test('every exception exists and still holds its word', () => {
    for (const k of jargonExceptions) {
      expect(fr[k], k).toBeDefined()
      expect(/\b(port|paquet|SSH)\b/i.test(fr[k]), k).toBe(true)
    }
  })
  test('the families are not empty', () => {
    expect(simpleEntries.length).toBeGreaterThan(0)
  })
})
