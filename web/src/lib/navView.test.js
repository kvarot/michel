import { describe, expect, test } from 'vitest'
import { activeEntry, entriesFor, navEntries, navMode, openBadge, pageOf } from './navView.js'
import { serversHash, serversRoute } from './serversView.js'

describe('navEntries', () => {
  test('has the seven pages, in order, with their addresses and groups', () => {
    expect(navEntries.map((e) => [e.page, e.hash, e.group])).toEqual([
      ['todo', '#/', 'follow'],
      ['findings', '#/findings', 'follow'],
      ['resolved', '#/resolved', 'follow'],
      ['reports', '#/reports', 'follow'],
      ['projects', '#/projects', 'park'],
      ['servers', '#/servers', 'park'],
      ['settings', '#/settings', 'other'],
    ])
    for (const e of navEntries) {
      expect(e.key).toBe(`nav.${e.page}`)
      expect(e.shortKey).toBe(`nav.short.${e.page}`)
      expect(e.icon.length).toBeGreaterThan(10)
    }
  })
  test('the side menu has every entry in three groups', () => {
    const side = entriesFor('side')
    expect(side.map((g) => [g.group, g.entries.map((e) => e.page)])).toEqual([
      ['follow', ['todo', 'findings', 'resolved', 'reports']],
      ['park', ['projects', 'servers']],
      ['other', ['settings']],
    ])
  })
  test('the bottom bar has five entries at most, the resolved problems and the reports left to the overview', () => {
    const bottom = entriesFor('bottom')
    expect(bottom).toHaveLength(1)
    expect(bottom[0].entries.map((e) => e.page)).toEqual(['todo', 'findings', 'projects', 'servers', 'settings'])
    expect(bottom[0].entries.length).toBeLessThanOrEqual(5)
  })
})

describe('pageOf', () => {
  test('pageOf reads every hash', () => {
    expect(pageOf('')).toBe('todo')
    expect(pageOf('#/')).toBe('todo')
    expect(pageOf('#/projects')).toBe('projects')
    expect(pageOf('#/servers')).toBe('servers')
    expect(pageOf('#/servers/a')).toBe('servers')
    expect(pageOf('#/servers/a?finding=b')).toBe('servers')
    expect(pageOf('#/resolved')).toBe('resolved')
    expect(pageOf('#/reports')).toBe('reports')
    expect(pageOf('#/reports?period=month&at=2026-10-01')).toBe('reports')
    expect(pageOf('#/reportsx')).toBe('todo')
    expect(pageOf('#/settings')).toBe('settings')
    expect(pageOf('#/findings')).toBe('findings')
    expect(pageOf('#/findings?project=shop&q=a%20b')).toBe('findings')
    expect(pageOf('#/findingsx')).toBe('todo')
    expect(pageOf('#/sources')).toBe('sources')
    expect(pageOf('#/fix')).toBe('fix')
    expect(pageOf('#/fix/abc')).toBe('fix')
    expect(pageOf('#/fix?finding=x')).toBe('fix')
    expect(pageOf('#/nothing')).toBe('todo')
    expect(pageOf('#/projectsx')).toBe('todo')
  })
})

describe('activeEntry', () => {
  test('activeEntry highlights the parent', () => {
    expect(activeEntry('fix')).toBe('findings')
    expect(activeEntry('sources')).toBe('settings')
    for (const p of ['todo', 'findings', 'projects', 'servers', 'resolved', 'reports', 'settings']) expect(activeEntry(p)).toBe(p)
  })
  test('at the bottom the resolved problems light the overview, which leads to them', () => {
    expect(activeEntry('resolved', 'bottom')).toBe('todo')
    expect(activeEntry('resolved', 'side')).toBe('resolved')
    expect(activeEntry('reports', 'bottom')).toBe('todo')
    expect(activeEntry('reports', 'side')).toBe('reports')
    expect(activeEntry('fix', 'bottom')).toBe('findings')
  })
})

describe('openBadge', () => {
  test('sums the open counts of every project, zeros included', () => {
    const digest = { projects: [{ name: 'shop', open: { critical: 1, high: 0, medium: 2, low: 0, unknown: 0 } }, { name: 'blog', open: { critical: 0, high: 0, medium: 0, low: 0, unknown: 3 } }] }
    expect(openBadge(digest)).toBe(6)
    expect(openBadge({ projects: [{ name: 'demo', open: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } }] })).toBe(0)
    expect(openBadge({ projects: [] })).toBe(0)
  })
  test('is null, never 0, when a count cannot be read', () => {
    expect(openBadge(null)).toBe(null)
    expect(openBadge({})).toBe(null)
    expect(openBadge({ projects: [{ name: 'shop' }] })).toBe(null)
    expect(openBadge({ projects: [{ name: 'shop', open: { high: 'x' } }] })).toBe(null)
    expect(openBadge({ projects: [{ name: 'shop', open: { high: -1 } }] })).toBe(null)
  })
})

describe('navMode', () => {
  test('navMode switches at 960', () => {
    for (const w of [375, 840, 959]) expect(navMode(w)).toBe('bottom')
    for (const w of [960, 1280]) expect(navMode(w)).toBe('side')
  })
})

describe('servers addresses', () => {
  test('serversRoute keeps old addresses', () => {
    expect(serversRoute('#/servers')).toEqual({ id: '', finding: '' })
    expect(serversRoute('#/servers/01SRV')).toEqual({ id: '01SRV', finding: '' })
    expect(serversRoute('#/servers/')).toEqual({ id: '', finding: '' })
    expect(serversRoute('#/serversx')).toBe(null)
  })
  test('serversRoute decodes finding', () => {
    expect(serversRoute('#/servers/a?finding=b')).toEqual({ id: 'a', finding: 'b' })
    expect(serversRoute('#/servers/a%20b?finding=f%201')).toEqual({ id: 'a b', finding: 'f 1' })
    expect(serversHash('a', 'f 1')).toBe('#/servers/a?finding=f%201')
    expect(serversHash('a')).toBe('#/servers/a')
    expect(serversHash('', 'f')).toBe('#/servers')
  })
})
