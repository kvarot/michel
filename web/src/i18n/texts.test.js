import { describe, expect, test } from 'vitest'
import en from './en.json'
import fr from './fr.json'

describe('safety texts', () => {
  test('the server fix intro does not say nothing runs without a click (level 3 rules do)', () => {
    expect(fr['fix.intro_server']).toContain('ou celle des règles que tu as autorisées')
    expect(en['fix.intro_server']).toContain('or that of the rules you allowed')
  })
  test('the backup hint shows which names to replace', () => {
    expect(fr['srvfix.backup_hint']).toContain('cp <sauvegarde> <fichier>')
    expect(fr['servers.hostkey.keep']).toBe("Garder l'ancienne empreinte")
  })
})
