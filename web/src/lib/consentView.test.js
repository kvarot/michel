import { describe, expect, test } from 'vitest'
import { readFileSync } from 'node:fs'
import fr from '../i18n/fr.json'
import en from '../i18n/en.json'
import { consentView } from './consentView.js'
import { findJargon } from '../i18n/jargon.js'

const novice = ['strict_local', 'politique', 'mode standard', 'composer', 'npm', 'packagist', 'api.github.com', '.bak']

describe('consentView', () => {
  test('a project: its own paragraph, the switch paragraph only under strict_local', () => {
    expect(consentView({ kind: 'project', switchMode: false, advanced: false }).plain).toEqual(['fix.consent.plain_project'])
    expect(consentView({ switchMode: true, advanced: false }).plain).toEqual(['fix.consent.plain_project', 'fix.consent.plain_switch'])
  })
  test('a server: its own paragraph, never the project’s', () => {
    expect(consentView({ kind: 'server', switchMode: false, advanced: false, lines: [{ what: 'fix.consent.server_what_leaves' }] }).plain).toEqual(['fix.consent.plain_server'])
    expect(consentView({ kind: 'server', switchMode: true, advanced: false, lines: [] }).plain).toEqual(['fix.consent.plain_server', 'fix.consent.plain_switch'])
  })
  test('a health server: nothing is said to go out', () => {
    const v = consentView({ kind: 'server', switchMode: true, advanced: false, lines: [{ what: 'fix.consent.server_health' }] })
    expect(v.plain).toEqual(['fix.consent.plain_server_health'])
    expect(fr['fix.consent.plain_server_health']).not.toMatch(/part|envoy/)
    expect(fr['fix.consent.plain_server_health']).toContain('rien')
  })
  test('the advanced mode shows the whole text, as before', () => {
    const v = consentView({ switchMode: true, advanced: true })
    expect(v).toMatchObject({ plain: [], detailOpen: true, accept: 'fix.consent.strict_accept' })
    expect(consentView({ switchMode: false, advanced: true }).accept).toBe('fix.consent.accept')
  })
  test('the detail only exists where there is technical wording to fold (the switch)', () => {
    expect(consentView({ switchMode: false, advanced: false }).detailButton).toBe(false)
    expect(consentView({ switchMode: true, advanced: false }).detailButton).toBe(true)
  })
})

describe('the plain words are true for their kind', () => {
  test('a project: files of the copy go out to Anthropic, a key Michel knows stops the agent, one it does not know can go; nothing claims files are masked', () => {
    const t = fr['fix.consent.plain_project']
    expect(t).toContain('Anthropic')
    expect(t).toContain('fichiers')
    expect(t).toContain('ne démarre pas')
    expect(t).toContain('ne reconnaît pas peut partir')
    expect(t).not.toMatch(/masqu/)
    expect(en['fix.consent.plain_project']).toContain('Anthropic')
    expect(en['fix.consent.plain_project']).not.toMatch(/mask/)
  })
  test('a server: versions and settings go out, secrets Michel knows are removed, the agent never connects', () => {
    const t = fr['fix.consent.plain_server']
    expect(t).toContain('Anthropic')
    expect(t).toContain('versions')
    expect(t).toContain('réglages')
    expect(t).toContain('ne se connecte jamais')
    expect(t).not.toContain('ton code')
    expect(en['fix.consent.plain_server']).toContain('never connects')
  })
  test('no word of the novice’s list, in both languages, and no unexplained jargon', () => {
    for (const k of ['fix.consent.plain_project', 'fix.consent.plain_server', 'fix.consent.plain_server_health', 'fix.consent.plain_switch', 'fix.consent.accept_plain', 'fix.consent.accept_plain_switch', 'fix.consent.detail']) {
      expect(fr[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
      for (const w of novice) expect(fr[k], `${k} ${w}`).not.toContain(w)
      expect(findJargon(fr[k]), k).toEqual([])
    }
  })
})

describe('what decides the consent is never folded', () => {
  const dialog = readFileSync(new URL('../components/AiConsentDialog.vue', import.meta.url), 'utf8')
  test('the lines of the server sit outside the details element, whatever the mode', () => {
    const details = dialog.match(/<details[\s\S]*?<\/details>/)[0]
    expect(details).not.toContain('lines')
    expect(details).not.toContain('l.text')
    expect(dialog).toMatch(/v-for="\(l, i\) in lines"/)
  })
  test('the server’s own sheet says it is a server’s consent', () => {
    const sheet = readFileSync(new URL('../components/ServerSheet.vue', import.meta.url), 'utf8')
    expect(sheet).toMatch(/<AiConsentDialog[^>]*kind="server"/)
  })
})
