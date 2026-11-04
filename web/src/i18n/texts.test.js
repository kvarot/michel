import { describe, expect, test } from 'vitest'
import en from './en.json'
import fr from './fr.json'

describe('safety texts', () => {
  test('the server fix intro does not say nothing runs without a click (level 3 rules do)', () => {
    expect(fr['fix.intro_server']).toContain('ou une règle que tu as toi-même activée')
    expect(en['fix.intro_server']).toContain('or a rule you turned on yourself')
  })
  test('the backup hint shows which names to replace', () => {
    expect(fr['srvfix.backup_hint']).toContain('cp <sauvegarde> <fichier>')
    expect(fr['servers.hostkey.keep']).toBe("Garder l'ancienne empreinte")
  })
})

describe('catalogs', () => {
  test('i18n catalogs have the same keys', () => {
    const f = Object.keys(fr)
    const e = Object.keys(en)
    expect(f.filter((k) => !(k in en))).toEqual([])
    expect(e.filter((k) => !(k in fr))).toEqual([])
  })
})

describe('the branch is ready (B4)', () => {
  test('the sentence tells what exists and no next step: the merge step of the page does, and it knows the project', () => {
    for (const [cat, bad] of [[fr, ['PhpStorm', 'Fais-la entrer', "d'habitude", 'en service']], [en, ['PhpStorm', 'Merge it', 'as usual', 'deploy']]]) {
      for (const w of bad) expect(cat['fix.chat.applied'], w).not.toContain(w)
    }
  })
})

describe('the source a server check needs (B6)', () => {
  test('says what it gives, in plain words, and what turning it on allows', () => {
    const t = fr['servers.sheet.source']
    expect(t).toContain('{key}')
    expect(t).toContain('liste publique de failles connues')
    expect(t).toContain('télécharger')
    expect(t).not.toContain('Active-la sur la page Sources')
    expect(en['servers.sheet.source']).toContain('public list of known flaws')
    expect(fr['servers.sheet.source_open']).toContain('Sources')
  })
})

describe('the Git question for someone who does not know (B7, words)', () => {
  test('explains the services, offers « Je ne sais pas » and what it means, and does not push a yes', () => {
    expect(fr['git.question']).toContain('où l\'on partage du code')
    expect(fr['git.why']).toContain('Je ne sais pas')
    expect(fr['git.why']).toContain('n\'envoie rien')
    expect(en['git.why']).toContain('I don\'t know')
    for (const k of ['git.suggest.known', 'git.suggest.other', 'git.suggest.none']) {
      expect(fr[k], k).not.toContain('La réponse semble')
      expect(en[k], k).not.toContain('The answer seems')
    }
    expect(fr['git.suggest.other']).toContain('Je ne sais pas')
  })
  test('« rattacher » is said « relier », and no editor is named in a next step', () => {
    for (const [k, v] of Object.entries(fr)) if (k.startsWith('git.')) expect(v, k).not.toMatch(/rattach/i)
    for (const [k, v] of Object.entries({ ...fr, ...en })) if (k.startsWith('git.') || k.startsWith('fix.')) expect(v, k).not.toContain('PhpStorm')
  })
})
