import { readFileSync } from 'node:fs'
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
    expect(t).toContain('failles connues')
    expect(t).toContain('liste publique')
    expect(t).toContain('télécharge')
    expect(t).not.toContain('à jour')
    expect(t).not.toContain('Active-la sur la page Sources')
    expect(en['servers.sheet.source']).toContain('public list')
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

describe('the words of the novice’s list are explained where they appear (T16)', () => {
  test('server words', () => {
    expect(fr['servers.discover.host']).toContain('un nom comme')
    expect(fr['servers.settings.sudo']).toContain('administrateur')
    expect(fr['srvfix.rollback.config']).toContain('le programme qui fait tourner ton site')
  })
  test('project words', () => {
    expect(fr['fix.proposal.tests_not_run_hint']).not.toContain('fusionner')
    expect(fr['fix.proposal.approve_hint']).toContain('une version à part de ton code')
    expect(fr['fix.done.inconclusive']).toContain('une version à part de ton code')
  })
  test('the English counterparts say as much', () => {
    expect(en['servers.settings.sudo']).toContain('administrator')
    expect(en['fix.proposal.approve_hint']).toContain('a version apart from your code')
  })
})

describe('the hand over says what the code does (I5, I11)', () => {
  test('the site is checked only if its address was given; the attempt ends if the script would change', () => {
    for (const k of ['srvfix.handover.body', 'srvfix.handover.body_plain']) {
      expect(fr[k]).toContain('si tu as donné l\'adresse du site')
      expect(fr[k]).toContain('cette correction s\'arrête')
      expect(fr[k]).toContain('Je l\'ai appliqué')
      expect(en[k]).toContain('if you gave the site\'s address')
      expect(en[k]).toContain('this fix stops')
    }
    expect(fr['srvfix.handover.body_plain']).toContain('le compte que Michel utilise')
    expect(fr['srvfix.handover.body_plain']).not.toContain('de ta connexion')
    expect(fr['srvfix.handover.ready']).not.toContain('Tu as changé')
    expect(en['srvfix.handover.ready']).not.toContain('You changed')
  })
  test('a software update: it does not undo, the date of the snapshot is the only way back', () => {
    for (const cat of [fr, en]) expect(cat['srvfix.handover.snapshot']).toContain('{date}')
    expect(fr['srvfix.handover.snapshot']).toContain('ne s\'annule pas')
    expect(en['srvfix.handover.snapshot']).toContain('cannot be undone')
    const c = readFileSync(new URL('../components/ServerProposal.vue', import.meta.url), 'utf8')
    expect(c).toMatch(/v-if="needsSnap"[^>]*>\{\{ \$t\('srvfix\.handover\.snapshot'/)
  })
  test('a server set to report only: the sentence that explains the missing button says so', () => {
    expect(fr['srvfix.handover.settings']).toContain('Signaler')
    expect(en['srvfix.handover.settings']).toContain('Report')
  })
})
