import { describe, expect, test } from 'vitest'
import { activeEntry, navEntries, navMode, pageOf } from './navView.js'
import { serversHash, serversRoute } from './serversView.js'

describe('navEntries', () => {
  test('has the five pages, in order, with their addresses', () => {
    expect(navEntries.map((e) => [e.page, e.hash])).toEqual([
      ['todo', '#/'],
      ['projects', '#/projects'],
      ['servers', '#/servers'],
      ['resolved', '#/resolved'],
      ['settings', '#/settings'],
    ])
    for (const e of navEntries) {
      expect(e.key).toBe(`nav.${e.page}`)
      expect(e.shortKey).toBe(`nav.short.${e.page}`)
      expect(e.icon.length).toBeGreaterThan(10)
    }
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
    expect(pageOf('#/settings')).toBe('settings')
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
    expect(activeEntry('fix')).toBe('todo')
    expect(activeEntry('sources')).toBe('settings')
    for (const p of ['todo', 'projects', 'servers', 'resolved', 'settings']) expect(activeEntry(p)).toBe(p)
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
