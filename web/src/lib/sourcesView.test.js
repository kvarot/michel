import { describe, expect, test } from 'vitest'
import {
  agoText, badgeKeys, consentSentence, groupByKind, kinds, lastReadText, rowActions, stateLabelKey, summary, switchOn,
} from './sourcesView.js'
import { translate } from '../i18n/index.js'

const t = (key, params) => translate('fr', key, params)
const en = (key, params) => translate('en', key, params)

describe('sourcesView', () => {
  test('groupByKind keeps the fixed order and leaves empty kinds out', () => {
    const groups = groupByKind([
      { key: 'ref.cve-org', kind: 'reference' },
      { key: 'feed.nginx', kind: 'feed' },
      { key: 'osv.npm', kind: 'osv' },
      { key: 'mcp.semgrep', kind: 'mcp' },
      { key: 'enrich.kev', kind: 'enrichment' },
      { key: 'osv.packagist', kind: 'osv' },
      { key: 'skill.demo', kind: 'skill' },
      { key: 'plugin.trivy', kind: 'plugin' },
      { key: 'x.y', kind: 'unknown' },
    ])
    expect(groups.map((g) => g.kind)).toEqual(['osv', 'enrichment', 'feed', 'plugin', 'skill', 'mcp', 'reference'])
    expect(groups[0].sources.map((s) => s.key)).toEqual(['osv.npm', 'osv.packagist'])
    expect(groupByKind([{ key: 'feed.a', kind: 'feed' }]).map((g) => g.kind)).toEqual(['feed'])
    expect(groupByKind(null)).toEqual([])
    expect(kinds).toEqual(['osv', 'enrichment', 'feed', 'plugin', 'skill', 'mcp', 'reference'])
  })

  test('stateLabelKey', () => {
    expect(stateLabelKey('on')).toBe('sources.state.on')
    expect(stateLabelKey('waiting_consent')).toBe('sources.state.waiting_consent')
    expect(stateLabelKey('off')).toBe('sources.state.off')
    expect(stateLabelKey('hidden')).toBe('sources.state.hidden')
    expect(stateLabelKey('bogus')).toBe('sources.state.off')
    expect(t(stateLabelKey('waiting_consent'))).toBe('attend ton accord')
  })

  test('switchOn: a source waiting for consent shows off, so turning it on asks for the consent', () => {
    expect(switchOn({ state: 'on', enabled: true })).toBe(true)
    expect(switchOn({ state: 'waiting_consent', enabled: true })).toBe(false)
    expect(switchOn({ state: 'off', enabled: false })).toBe(false)
    expect(switchOn({ state: 'hidden', enabled: true })).toBe(false)
    expect(switchOn(null)).toBe(false)
  })

  test('rowActions: a source waiting for consent can be turned off', () => {
    const waiting = { kind: 'enrichment', state: 'waiting_consent', enabled: true, origin: 'catalog' }
    expect(rowActions(waiting)).toEqual(['detail', 'disable', 'update', 'remove', 'reset'])
    expect(rowActions({ ...waiting, state: 'on' })).not.toContain('disable')
    expect(rowActions({ kind: 'feed', state: 'off', enabled: false, origin: 'user' })).toEqual(['detail', 'remove'])
    expect(rowActions({ kind: 'skill', state: 'on', enabled: true, origin: 'catalog' })).toEqual(['detail', 'update', 'install', 'remove', 'reset'])
    expect(rowActions({ kind: 'skill', state: 'on', enabled: true, config: { installed: true }, badges: ['new_version'] })).toContain('upgrade')
    expect(rowActions({ kind: 'plugin', state: 'on', enabled: true })).toEqual(['detail', 'update', 'run', 'remove'])
    expect(rowActions({ kind: 'reference', state: 'hidden', enabled: true, origin: 'catalog' })).toEqual(['detail', 'reset'])
    expect(t('sources.action.disable')).toBe('Refuser et désactiver cette source')
    expect(en('sources.action.disable')).toBe('Decline and disable this source')
  })

  test('badgeKeys for new_version, suggested and archived', () => {
    expect(badgeKeys({ badges: ['new_version', 'suggested', 'archived'] })).toEqual([
      'sources.badge.new_version', 'sources.badge.suggested', 'sources.badge.archived',
    ])
    expect(badgeKeys({ badges: ['archived', 'other'] })).toEqual(['sources.badge.archived'])
    expect(badgeKeys({})).toEqual([])
    expect(t('sources.badge.suggested')).toBe('suggérée pour toi')
    expect(t('sources.badge.new_version')).toBe('nouvelle version')
  })

  test('consentSentence uses the server text, else says the host', () => {
    const what = 'Michel va contacter www.cisa.gov pour télécharger une liste publique sur les failles.'
    expect(consentSentence({ host: 'www.cisa.gov', what }, t)).toBe(what)
    expect(consentSentence({ host: 'www.cisa.gov', what: '' }, t)).toBe(t('consent.contact', { host: 'www.cisa.gov' }))
    expect(consentSentence({ host: 'www.cisa.gov' }, t)).toContain('www.cisa.gov')
    expect(consentSentence(null, t)).toBe('')
  })

  test('agoText and lastReadText', () => {
    const now = new Date('2026-10-29T08:31:00Z')
    expect(agoText('2026-10-29T08:30:30Z', now, t)).toBe("à l'instant")
    expect(agoText('2026-10-29T08:01:00Z', now, t)).toBe('il y a 30 min')
    expect(agoText('2026-10-29T06:31:00Z', now, t)).toBe('il y a 2 h')
    expect(agoText('2026-10-27T08:31:00Z', now, t)).toBe('il y a 2 jours')
    expect(agoText('', now, t)).toBe('')
    expect(lastReadText({ at: '2026-10-29T06:31:00Z', result: 'ok', items: 14 }, now, t)).toBe('il y a 2 h · 14 nouveautés')
    expect(lastReadText({ at: '2026-10-29T06:31:00Z', result: 'ok', items: 1 }, now, en)).toBe('2 h ago · 1 new item')
    expect(lastReadText({ at: '', result: '' }, now, t)).toBe(t('sources.last.never'))
    expect(lastReadText({ at: '2026-10-29T06:31:00Z', result: 'error', error: 'EOF' }, now, en)).toBe('2 h ago · could not be read: EOF')
    expect(lastReadText({ at: '2026-10-29T06:31:00Z', result: 'waiting_consent' }, now, t)).toContain('accord')
    expect(lastReadText({ at: '2026-10-29T06:31:00Z', result: 'strange' }, now, en)).toBe('2 h ago')
  })

  test('summary counts the sources on and waiting, and the last read', () => {
    const s = summary([
      { state: 'on', last_read: { at: '2026-10-29T06:31:00Z', result: 'ok' } },
      { state: 'on', last_read: { at: '2026-10-28T06:31:00Z', result: 'ok' } },
      { state: 'waiting_consent', last_read: { at: '2026-10-29T07:00:00Z', result: 'waiting_consent' } },
      { state: 'off', last_read: { at: '', result: '' } },
    ])
    expect(s).toEqual({ on: 2, waiting: 1, lastAt: '2026-10-29T06:31:00Z' })
    expect(summary([])).toEqual({ on: 0, waiting: 0, lastAt: '' })
  })
})
