import { readdirSync, readFileSync } from 'node:fs'
import { describe, expect, test } from 'vitest'
import fr from './fr.json'
import { catalogJargon, findJargon } from './jargon.js'

// The whole catalog is read, minus the families only advanced mode shows. A family
// goes here only with its proof below: where it is used, and behind what.
const advancedOnly = ['fact.', 'term.']
// Keys allowed to use port, paquet or SSH because their own sentence explains it.
// A task that adds one lists it here, in the same commit.
// help.server.port explains the word port in its own sentence, plan.server.approval_michel the word SSH.
// git.suggest.unsupported explains SSH in its own sentence.
// expo.udp.note says what TCP is ("le type le plus courant") and that the others are not read; expo.udp.name is its title, shown with it.
// servers.discover.port gives the plain name first, for the word a host's page uses; servers.discover.key_only says what the SSH agent is.
// servers.hostkey.first holds a command to type as it is, and says who types it; servers.remove.rules_not_removed holds the names written in the file to edit, and says whom to ask.
const jargonExceptions = [
  'help.server.port', 'plan.server.approval_michel', 'expo.udp.name', 'expo.udp.note', 'git.suggest.unsupported',
  'servers.discover.port', 'servers.discover.key_only', 'servers.hostkey.first', 'servers.remove.rules_not_removed',
]

const rules = { exempt: advancedOnly, exceptions: jargonExceptions }

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

describe('no unexplained jargon in the catalog', () => {
  test('the whole catalog, minus what only advanced mode shows', () => {
    expect(catalogJargon(fr, rules)).toEqual([])
  })
  test('a planted word fails, in any family', () => {
    expect(catalogJargon({ ...fr, 'servers.planted': 'Michel lit par SSH.' }, rules)).toEqual(['servers.planted: port, paquet or SSH'])
    expect(catalogJargon({ ...fr, 'nouvelle.famille': 'Un paquet ancien.' }, rules)).toEqual(['nouvelle.famille: port, paquet or SSH'])
    expect(catalogJargon({ ...fr, 'guide.planted': 'La faille CVE-2024-1.' }, rules)).toEqual(['guide.planted: identifier word'])
  })
  test('a key of a family that is only advanced is left out, and only those', () => {
    expect(catalogJargon({ ...fr, 'fact.planted': 'par SSH' }, rules)).toEqual([])
    expect(catalogJargon({ ...fr, 'factory.planted': 'par SSH' }, rules)).toEqual(['factory.planted: port, paquet or SSH'])
  })
  test('every exception exists and still holds its word', () => {
    for (const k of jargonExceptions) {
      expect(fr[k], k).toBeDefined()
      expect(findJargon(fr[k]).filter((w) => w !== 'identifier word'), k).not.toEqual([])
    }
  })
})

describe('what is left out is only shown in advanced mode', () => {
  const read = (dir) => readdirSync(new URL(dir, import.meta.url))
    .filter((f) => /\.(vue|js)$/.test(f) && !f.endsWith('.test.js'))
    .map((f) => ({ file: `${dir}${f}`, text: readFileSync(new URL(`${dir}${f}`, import.meta.url), 'utf8') }))
  const sources = [...read('../components/'), ...read('../lib/'), ...read('../')]
  const usesAdvancedOnly = /['"`](fact|term)\./

  test('these families are used in one file', () => {
    expect(sources.filter((s) => usesAdvancedOnly.test(s.text)).map((s) => s.file)).toEqual(['../components/FindingSheet.vue'])
  })
  test('in it, only inside the blocks that advanced mode opens', () => {
    const sheet = sources.find((s) => s.file.endsWith('FindingSheet.vue')).text
    const outside = sheet
      .replace(/<dl v-if="\$ui\.advanced"[\s\S]*?<\/dl>/, '')
      .replace(/<details v-if="\$ui\.advanced"[\s\S]*?<\/details>/, '')
      .replace(/<section v-if="\$ui\.advanced && glossaryList\.length"[\s\S]*?<\/section>/, '')
    expect(outside).not.toBe(sheet)
    expect(outside.match(/['"`](fact|term)\.[^'"`]*/g)).toBeNull()
  })
})
