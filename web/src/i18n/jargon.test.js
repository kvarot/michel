import { describe, expect, test } from 'vitest'
import fr from './fr.json'
import { findJargon } from './jargon.js'

// Families of texts a novice reads in simple mode. The exploited banner stays
// visible in simple mode, so its texts are checked too.
const families = ['nav.', 'todo.', 'resolved.', 'path.', 'plan.', 'expo.', 'guide.', 'empty.', 'help.', 'git.', 'exploited.']
// Keys allowed to use port, paquet or SSH because their own sentence explains it.
// Empty for now: a task that adds one lists it here, in the same commit.
const jargonExceptions = []

const simpleEntries = Object.entries(fr).filter(([k]) => families.some((f) => k.startsWith(f)))

describe('findJargon', () => {
  test('fires on a planted string, singular and plural', () => {
    expect(findJargon('3 ports ouverts')).toEqual(['port, paquet or SSH'])
    expect(findJargon('Un paquet ancien')).toEqual(['port, paquet or SSH'])
    expect(findJargon('Deux paquets')).toEqual(['port, paquet or SSH'])
    expect(findJargon('par SSH')).toEqual(['port, paquet or SSH'])
    expect(findJargon('La faille CVE-2024-1 est ouverte')).toEqual(['identifier word'])
    expect(findJargon('score CVSS et EPSS')).toEqual(['identifier word'])
  })
  test('lets plain sentences and exceptions through', () => {
    expect(findJargon('Michel a trouvé une faille.')).toEqual([])
    expect(findJargon('3 ports ouverts', true)).toEqual([])
    expect(findJargon('par SSH', true)).toEqual([])
  })
})

describe('no unexplained jargon in simple texts', () => {
  test('no unexplained jargon in simple texts', () => {
    const bad = []
    for (const [k, v] of simpleEntries) {
      for (const why of findJargon(v, jargonExceptions.includes(k))) bad.push(`${k}: ${why}`)
    }
    expect(bad).toEqual([])
  })
  test('every exception exists and still holds its word', () => {
    for (const k of jargonExceptions) {
      expect(fr[k], k).toBeDefined()
      expect(findJargon(fr[k]), k).toContain('port, paquet or SSH')
    }
  })
  test('the families are not empty', () => {
    expect(simpleEntries.length).toBeGreaterThan(0)
  })
})
