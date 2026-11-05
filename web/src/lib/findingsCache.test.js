import { describe, expect, test } from 'vitest'
import { createCache, stampOf } from './findingsCache.js'

const shop = { name: 'shop', last_scan_at: '2026-11-01T10:00:00Z', total: 2, last_scan_status: 'done' }
const blog = { name: 'blog', last_scan_at: '2026-11-02T10:00:00Z', total: 0, last_scan_status: 'done' }

describe('findingsCache', () => {
  test('a list read is given back for the same project, stamp and language', () => {
    const c = createCache()
    c.keep('fr', [shop, blog], { shop: [{ id: 'a' }], blog: [] })
    expect(c.lists('fr', [shop, blog])).toEqual({ shop: [{ id: 'a' }], blog: [] })
    expect(c.lists('en', [shop, blog])).toEqual({})
  })
  test('a new check of a project makes it read again', () => {
    const c = createCache()
    c.keep('fr', [shop], { shop: [{ id: 'a' }] })
    expect(c.lists('fr', [{ ...shop, last_scan_at: '2026-11-03T10:00:00Z' }])).toEqual({})
    expect(c.lists('fr', [{ ...shop, total: 3 }])).toEqual({})
    expect(c.lists('fr', [{ ...shop, last_scan_status: 'failed' }])).toEqual({})
  })
  test('a list not read is not kept, and nothing is kept without projects', () => {
    const c = createCache()
    c.keep('fr', [shop, blog], { shop: null, blog: [] })
    expect(c.lists('fr', [shop, blog])).toEqual({ blog: [] })
    c.keep('fr', null, { shop: [] })
    expect(c.lists('fr', [shop])).toEqual({})
    expect(c.lists('fr', null)).toEqual({})
  })
  test('the digests are kept by language; clear forgets everything', () => {
    const c = createCache()
    expect(c.runs('fr')).toBe(null)
    c.keepRuns('fr', null)
    expect(c.runs('fr')).toBe(null)
    c.keepRuns('fr', [])
    expect(c.runs('fr')).toEqual([])
    expect(c.runs('en')).toBe(null)
    c.keep('fr', [shop], { shop: [] })
    c.clear()
    expect(c.runs('fr')).toBe(null)
    expect(c.lists('fr', [shop])).toEqual({})
  })
  test('stampOf', () => {
    expect(stampOf(shop)).toBe('2026-11-01T10:00:00Z|2|done')
    expect(stampOf(null)).toBe('||')
  })
})
