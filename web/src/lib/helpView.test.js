import { describe, expect, test } from 'vitest'
import en from '../i18n/en.json'
import fr from '../i18n/fr.json'
import { helpIds, helpIdsIn, helpKey, maxHelpLength } from './helpView.js'

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
  test('the reader finds ids in a source', () => {
    expect(helpIdsIn('<FieldHelp id="a.b" :field="x" />\n<FieldHelp\n  :field="y" id="c.d"/>')).toEqual(['a.b', 'c.d'])
  })
})
