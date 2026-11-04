import { describe, expect, test } from 'vitest'
import fr from '../i18n/fr.json'
import en from '../i18n/en.json'
import { visibleSheets } from './sheetsView.js'

describe('visibleSheets (B9)', () => {
  const ids = Array.from({ length: 14 }, (_, i) => `f${i}`)
  test('shows the first few and counts the others', () => {
    expect(visibleSheets(ids, false)).toEqual({ shown: ['f0', 'f1', 'f2'], hidden: 11 })
  })
  test('shows everything once asked: the list stays reachable', () => {
    expect(visibleSheets(ids, true)).toEqual({ shown: ids, hidden: 0 })
  })
  test('a short list is whole, with nothing to ask for', () => {
    expect(visibleSheets(['a', 'b', 'c'], false)).toEqual({ shown: ['a', 'b', 'c'], hidden: 0 })
    expect(visibleSheets([], false)).toEqual({ shown: [], hidden: 0 })
  })
  test('one more than the limit is still folded, as « et 1 autre »', () => {
    expect(visibleSheets(['a', 'b', 'c', 'd'], false).hidden).toBe(1)
  })
  test('the words, singular and plural, in both languages', () => {
    for (const cat of [fr, en]) for (const k of ['item.more.one', 'item.more.other', 'item.less']) expect(cat[k], k).toBeTruthy()
    expect(fr['item.more.one']).toContain('Et {n} autre faille')
    expect(fr['item.more.other']).toContain('Et {n} autres failles')
  })
})
