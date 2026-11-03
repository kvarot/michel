import { describe, expect, test } from 'vitest'
import { plainSentence, readAdvanced, stripTechnicalIds } from './modeView.js'
import { keys } from './storage.js'

describe('readAdvanced', () => {
  test('advanced defaults to off', () => {
    expect(readAdvanced(() => '')).toBe(false)
    expect(readAdvanced(() => 'yes')).toBe(false)
    expect(readAdvanced(() => 'true')).toBe(false)
    expect(readAdvanced(() => {
      throw new Error('blocked')
    })).toBe(false)
  })
  test('only the value 1 turns it on, under its own key', () => {
    let asked = ''
    expect(readAdvanced((k) => ((asked = k), '1'))).toBe(true)
    expect(asked).toBe(keys.advanced)
    expect(keys.advanced).toBe('michel.advanced')
  })
})

describe('stripTechnicalIds', () => {
  test('stripTechnicalIds removes ids and keeps the sentence', () => {
    expect(stripTechnicalIds('La faille CVE-2024-12345 permet de lire des fichiers.')).toBe('La faille permet de lire des fichiers.')
    expect(stripTechnicalIds('Corrigée (GHSA-abcd-1234-wxyz) dans la 2.0.')).toBe('Corrigée dans la 2.0.')
    expect(stripTechnicalIds('Voir PHP2Shell (CVE-2024-1111).')).toBe('Voir PHP2Shell.')
  })
  test('keeps names that only look close', () => {
    expect(stripTechnicalIds('PHP2Shell reste.')).toBe('PHP2Shell reste.')
    expect(stripTechnicalIds('')).toBe('')
    expect(stripTechnicalIds(undefined)).toBe('')
  })
})

describe('stripTechnicalIds leaves alone what no id touched', () => {
  test('a sentence without an id is returned as it is', () => {
    expect(stripTechnicalIds('Et voilà')).toBe('Et voilà')
    expect(stripTechnicalIds('And so on')).toBe('And so on')
    expect(stripTechnicalIds('Noir et')).toBe('Noir et')
    expect(stripTechnicalIds('Corrigée : voici pourquoi.')).toBe('Corrigée : voici pourquoi.')
  })
  test('an id in the middle does not clean the edges', () => {
    expect(stripTechnicalIds('Et voilà la faille CVE-2024-1111 corrigée.')).toBe('Et voilà la faille corrigée.')
  })
})

describe('stripTechnicalIds grammar', () => {
  test('capitalises a sentence that began with an id', () => {
    expect(stripTechnicalIds('CVE-2024-12345 permet de lire des fichiers.')).toBe('Permet de lire des fichiers.')
  })
  test('drops a dangling et or comma at the edges', () => {
    expect(stripTechnicalIds('CVE-2024-1111 et CVE-2024-2222 sont corrigées.')).toBe('Sont corrigées.')
    expect(stripTechnicalIds('Corrigées : CVE-2024-1111 et CVE-2024-2222')).toBe('Corrigées')
    expect(stripTechnicalIds('Failles CVE-2024-1111, CVE-2024-2222.')).toBe('Failles.')
    expect(stripTechnicalIds('Fixed: CVE-2024-1111 and CVE-2024-2222')).toBe('Fixed')
  })
})

describe('plainSentence', () => {
  test('the simple mode drops the file of a call site', () => {
    const f = { analysis: { calls: { sites: [{ file: 'src/Foo.php', line: 12 }] } } }
    expect(plainSentence("acme/lib 1.0 est utilisé à 3 endroits de ton code, par exemple src/Foo.php:12. L'avis dit : « a »", f))
      .toBe("acme/lib 1.0 est utilisé à 3 endroits de ton code. L'avis dit : « a »")
    expect(plainSentence('acme/lib 1.0 is used in 3 places in your code, for example src/Foo.php:12.', f))
      .toBe('acme/lib 1.0 is used in 3 places in your code.')
  })
  test('holds without the analysis, and for a file name with a space, given the site', () => {
    expect(plainSentence('Utilisé, par exemple src/Foo.php:12.', null)).toBe('Utilisé.')
    const f = { analysis: { calls: { sites: [{ file: 'my src/Foo.php', line: 3 }] } } }
    expect(plainSentence('Utilisé, par exemple my src/Foo.php:3.', f)).toBe('Utilisé.')
  })
  test('drops the rule and the place of a plugin finding', () => {
    const f = { rule_id: 'php.lang.security.exec-use', location: 'src/a.php:12' }
    expect(plainSentence('semgrep signale le problème php.lang.security.exec-use dans src/a.php:12.', f)).toBe('semgrep signale le problème.')
    expect(plainSentence('semgrep flags the problem php.lang.security.exec-use in src/a.php:12.', f)).toBe('semgrep flags the problem.')
  })
  test('drops the advisory id of the flaw and ids of CVE shape', () => {
    expect(plainSentence('La faille ACME-2026-0001 (CVE-2024-12345) est grave.', { osv_id: 'ACME-2026-0001' })).toBe('La faille est grave.')
  })
  test('leaves a plain sentence alone', () => {
    expect(plainSentence('Une phrase : sans rien, par exemple ceci.', {})).toBe('Une phrase : sans rien, par exemple ceci.')
    expect(plainSentence('', {})).toBe('')
  })
})
