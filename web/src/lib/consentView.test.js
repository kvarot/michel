import { describe, expect, test } from 'vitest'
import fr from '../i18n/fr.json'
import en from '../i18n/en.json'
import { consentView } from './consentView.js'
import { findJargon } from '../i18n/jargon.js'

describe('consentView', () => {
  test('the simple mode opens with the plain paragraph, the detail one click away', () => {
    expect(consentView({ switchMode: false, advanced: false })).toMatchObject({ plain: ['fix.consent.plain'], detailOpen: false, detailButton: true })
    expect(consentView({ switchMode: true, advanced: false }).plain).toEqual(['fix.consent.plain', 'fix.consent.plain_switch'])
  })
  test('the advanced mode shows the whole text, as before', () => {
    const v = consentView({ switchMode: true, advanced: true })
    expect(v).toMatchObject({ plain: [], detailOpen: true, detailButton: false, accept: 'fix.consent.strict_accept' })
    expect(consentView({ switchMode: false, advanced: true }).accept).toBe('fix.consent.accept')
  })
  test('the plain words name the company, say the code goes out and is masked, and use none of the words of the novice’s list', () => {
    for (const k of ['fix.consent.plain', 'fix.consent.plain_switch', 'fix.consent.accept_plain', 'fix.consent.accept_plain_switch', 'fix.consent.detail']) {
      expect(fr[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
      for (const w of ['strict_local', 'politique', 'mode standard', 'composer', 'npm', 'packagist', 'api.github.com', '.bak']) expect(fr[k], `${k} ${w}`).not.toContain(w)
      expect(findJargon(fr[k]), k).toEqual([])
    }
    expect(fr['fix.consent.plain']).toContain('Anthropic')
    expect(fr['fix.consent.plain']).toContain('part')
    expect(fr['fix.consent.plain']).toContain('masqu')
    expect(en['fix.consent.plain']).toContain('Anthropic')
    expect(en['fix.consent.plain']).toContain('masked')
  })
  test('the technical text stays in the catalog, for the detail', () => {
    for (const k of ['fix.consent.strict_intro', 'fix.consent.strict_change', 'fix.consent.intro']) expect(fr[k], k).toBeTruthy()
  })
})
