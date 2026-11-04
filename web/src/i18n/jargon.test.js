import { readFileSync } from 'node:fs'
import { describe, expect, test } from 'vitest'
import fr from './fr.json'
import { findJargon } from './jargon.js'

// Families of texts a novice reads in simple mode. The exploited banner stays
// visible in simple mode, so its texts are checked too.
const families = ['nav.', 'todo.', 'resolved.', 'path.', 'plan.', 'expo.', 'guide.', 'empty.', 'help.', 'git.', 'exploited.']
// Keys allowed to use port, paquet or SSH because their own sentence explains it.
// A task that adds one lists it here, in the same commit.
// help.server.port explains the word port in its own sentence, plan.server.approval_michel the word SSH.
// git.suggest.unsupported explains SSH in its own sentence.
// expo.udp.note says what TCP is ("le type le plus courant") and that the others are not read; expo.udp.name is its title, shown with it.
const jargonExceptions = ['help.server.port', 'plan.server.approval_michel', 'expo.udp.name', 'expo.udp.note', 'git.suggest.unsupported']

const simpleEntries = Object.entries(fr).filter(([k]) => families.some((f) => k.startsWith(f)))

describe('findJargon', () => {
  test('fires on a planted string, singular and plural', () => {
    expect(findJargon('3 ports ouverts')).toEqual(['port, paquet or SSH'])
    expect(findJargon('Un paquet ancien')).toEqual(['port, paquet or SSH'])
    expect(findJargon('Deux paquets')).toEqual(['port, paquet or SSH'])
    expect(findJargon('par SSH')).toEqual(['port, paquet or SSH'])
    expect(findJargon('Les services UDP')).toEqual(['network word'])
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
      expect(findJargon(fr[k]).filter((w) => w !== 'identifier word'), k).not.toEqual([])
    }
  })
  test('the exposure page only says words these rules look at', () => {
    // Every key of its sheet and of its dialog is in a family above, or a decision's own.
    const page = readFileSync(new URL('../components/ServerExposure.vue', import.meta.url), 'utf8')
    const keys = [...page.matchAll(/\$t\('([^']+)'/g)].map((m) => m[1])
    expect(keys.length).toBeGreaterThan(0)
    expect(keys.filter((k) => !families.some((f) => k.startsWith(f)) && !k.startsWith('decision.') && !['offline.hint', 'error.generic', 'app.retry', 'servers.sheet.check'].includes(k))).toEqual([])
  })
  test('the families are not empty', () => {
    expect(simpleEntries.length).toBeGreaterThan(0)
  })
})
