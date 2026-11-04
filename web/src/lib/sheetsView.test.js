import { describe, expect, test } from 'vitest'
import fr from '../i18n/fr.json'
import en from '../i18n/en.json'
import { rowFixable, visibleSheets } from './sheetsView.js'

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
  test('every flaw that must show is unfolded, however many: 5 critical of 14 hide none (I9)', () => {
    expect(visibleSheets(ids, false, 5)).toEqual({ shown: ids.slice(0, 5), hidden: 9 })
    expect(visibleSheets(ids, false, 1)).toEqual({ shown: ids.slice(0, 3), hidden: 11 })
    expect(visibleSheets(ids, false, 20)).toEqual({ shown: ids, hidden: 0 })
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

describe('rowFixable (D-4)', () => {
  const item = (extra = {}) => ({ kind: 'new', findingIds: ['a'], decided: '', ...extra })
  test('an open flaw of a project Michel can fix', () => {
    expect(rowFixable(item(), true)).toBe(true)
  })
  test('never a folder Michel can prepare no fix for', () => {
    expect(rowFixable(item(), false)).toBe(false)
  })
  test('never what left, nor what the person ignored', () => {
    expect(rowFixable(item({ kind: 'gone' }), true)).toBe(false)
    expect(rowFixable(item({ decided: 'ignore' }), true)).toBe(false)
    expect(rowFixable(item({ findingIds: [] }), true)).toBe(false)
  })
})
