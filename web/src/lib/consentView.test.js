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
    expect(consentView({ kind: 'server', switchMode: false, advanced: false }).plain).toEqual(['fix.consent.plain_server'])
    expect(consentView({ kind: 'server', switchMode: true, advanced: false }).plain).toEqual(['fix.consent.plain_server', 'fix.consent.plain_switch'])
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
    expect(t).toContain('tes messages')
    expect(t).toContain('la fiche de la faille')
    expect(t).not.toContain('mot de passe')
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
    for (const k of ['fix.consent.plain_project', 'fix.consent.plain_server', 'fix.consent.plain_switch', 'fix.consent.accept_plain', 'fix.consent.accept_plain_switch', 'fix.consent.detail']) {
      expect(fr[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
      for (const w of novice) expect(fr[k], `${k} ${w}`).not.toContain(w)
      expect(findJargon(fr[k]), k).toEqual([])
    }
  })
})

describe('what decides the consent is never folded', () => {
  const dialog = readFileSync(new URL('../components/AiConsentDialog.vue', import.meta.url), 'utf8')
  test('the simple mode folds names only: no line, no guarantee, no deciding sentence', () => {
    const folded = [...dialog.matchAll(/<details[\s\S]*?<\/details>/g)].map((m) => m[0]).join('')
    expect(folded).not.toContain('l.text')
    expect(folded).not.toContain('lines')
    expect(folded).not.toContain('strict_change')
    expect(folded).not.toContain('strict_intro')
    expect(folded).toContain('detail_names')
    expect(dialog).toMatch(/v-for="\(l, i\) in lines"/)
  })
  test('the plain switch paragraph carries all of the deciding sentence', () => {
    const t = fr['fix.consent.plain_switch']
    for (const w of ['garantie', 'rien ne sort', 'tu perds', 'adresses listées', 'tout Michel', 'revenir en arrière']) expect(t, w).toContain(w)
    const e = en['fix.consent.plain_switch']
    for (const w of ['guarantee', 'nothing leaves', 'you lose', 'addresses listed', 'all of Michel', 'go back']) expect(e, w).toContain(w)
  })
  test('the button says what it does: leaving the protection, not one AI', () => {
    expect(fr['fix.consent.accept_plain_switch']).toContain('quitter cette protection')
    expect(fr['fix.consent.accept_plain_switch']).not.toContain('cette IA')
    expect(en['fix.consent.accept_plain_switch']).toContain('leave this protection')
    expect(en['fix.consent.accept_plain_switch']).not.toContain('this AI')
  })
  test('the advanced mode has no fold to close', () => {
    expect(dialog).not.toMatch(/<details[^>]*:open/)
  })
  test('the lines Go writes hold no unexplained jargon', () => {
    const go = JSON.parse(readFileSync(new URL('../../../internal/i18n/catalog/fr.json', import.meta.url), 'utf8'))
    for (const k of ['fix.consent.runs_code', 'fix.consent.install', 'fix.consent.external_providers']) expect(findJargon(go[k]), k).toEqual([])
    expect(go['fix.consent.runs_code']).toContain('(composer, npm)')
    expect(go['fix.consent.runs_code']).not.toContain('composer/npm')
    expect(go['fix.consent.external_providers']).not.toContain('politique')
    expect(go['fix.consent.external_providers']).toContain('ai.external_providers_enabled')
    expect(go['fix.consent.install']).toContain('un site public')
  })
  test('the server’s own sheet says it is a server’s consent', () => {
    const sheet = readFileSync(new URL('../components/ServerSheet.vue', import.meta.url), 'utf8')
    expect(sheet).toMatch(/<AiConsentDialog[^>]*kind="server"/)
  })
})
