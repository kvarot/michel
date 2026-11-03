import { describe, expect, test } from 'vitest'
import en from '../i18n/en.json'
import fr from '../i18n/fr.json'
import { helpIds, helpIdsIn, helpKey, helpTagsIn, maxHelpLength } from './helpView.js'

const sources = import.meta.glob('../components/*.vue', { query: '?raw', import: 'default', eager: true })
const used = new Set()
for (const [path, src] of Object.entries(sources)) {
  if (path.endsWith('/FieldHelp.vue')) continue
  for (const id of helpIdsIn(src)) used.add(id)
}

describe('help texts', () => {
  test('every help id has fr and en text', () => {
    for (const id of helpIds) {
      expect(fr[helpKey(id)], `fr ${id}`).toBeTruthy()
      expect(en[helpKey(id)], `en ${id}`).toBeTruthy()
    }
    expect(fr['help.label']).toContain('{field}')
    expect(en['help.label']).toContain('{field}')
  })
  test('help stays short', () => {
    for (const id of helpIds) {
      expect(fr[helpKey(id)].length, `fr ${id}`).toBeLessThanOrEqual(maxHelpLength)
      expect(en[helpKey(id)].length, `en ${id}`).toBeLessThanOrEqual(maxHelpLength)
    }
  })
  test('the catalogs hold no help text without an id', () => {
    for (const cat of [fr, en]) {
      const keys = Object.keys(cat).filter((k) => k.startsWith('help.') && k !== 'help.label')
      expect(keys.filter((k) => !helpIds.includes(k.slice(5)))).toEqual([])
    }
  })
  test('ids are unique', () => {
    expect(new Set(helpIds).size).toBe(helpIds.length)
  })
})

describe('FieldHelp in the components', () => {
  test('every FieldHelp is listed', () => {
    expect([...used].filter((id) => !helpIds.includes(id))).toEqual([])
  })
  test('every listed id is shown somewhere', () => {
    expect(helpIds.filter((id) => !used.has(id))).toEqual([])
  })
  test('every FieldHelp tag has an id the test can read', () => {
    for (const [path, src] of Object.entries(sources)) {
      if (path.endsWith('/FieldHelp.vue')) continue
      expect(helpTagsIn(src), path).toBe(helpIdsIn(src).length)
    }
  })
  test('a tag the reader cannot read is counted, so it fails the test above', () => {
    for (const bad of ['<FieldHelp :id="x" :field="y" />', '<field-help id="a.b" :field="y" />', '<FieldHelp v-if="n > 1" id="a.b" :field="y" />']) {
      expect(helpTagsIn(bad), bad).toBe(1)
      expect(helpIdsIn(bad), bad).toEqual([])
    }
  })
  test('a named FieldHelp is read like the others', () => {
    expect(helpIdsIn('<FieldHelp named id="a.b" :field="x" />')).toEqual(['a.b'])
  })
  test('the proposals of a server and of a project have their own approve help', () => {
    const of = (name) => helpIdsIn(sources[`../components/${name}.vue`])
    expect(of('ServerProposal')).toContain('fix.approve_server')
    expect(of('ServerProposal')).not.toContain('fix.approve')
    expect(of('FixProposal')).toContain('fix.approve')
    expect(of('FixProposal')).not.toContain('fix.approve_server')
  })
  test('the reader finds ids in a source', () => {
    expect(helpIdsIn('<FieldHelp id="a.b" :field="x" />\n<FieldHelp\n  :field="y" id="c.d"/>')).toEqual(['a.b', 'c.d'])
  })
})
