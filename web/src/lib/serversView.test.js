import { describe, expect, test } from 'vitest'
import {
  backupLine, canApproveServer, envLabel, findingTitle, intervalLabel, isServerAttempt, kindLabel, levelLabel, mergeFindings, restoreNeeded,
  canOfferAgent, cardLine, cardOfFinding, doneKey, guideServerTitle, healthServer, lastAttemptOf, serverAttemptLine, serverLevels, serverPollDelay, serversHash, serversRoute, needsSnapshot, serverStateLine, sortFindings, stateSentence, stepLine, touchedServers,
} from './serversView.js'

const now = new Date('2026-11-01T12:00:00Z')

/** srv builds a TargetView as GET /targets answers it. */
function srv(extra = {}) {
  return {
    id: '01SRV', name: 'srv-demo', kind: 'vps', env: 'prod', fix_level: 1, check_interval: '24h', executor: 'user', sudo: 'none',
    active: true, host_key_pinned: true, last_check_at: '2026-11-01T09:00:00Z', open_findings: 0, checking: false,
    state: { code: 'clean', text: '' }, ...extra,
  }
}

describe('stateSentence', () => {
  test('touched: the number of flaws and when Michel last looked', () => {
    expect(stateSentence(srv({ open_findings: 2, state: { code: 'findings' } }), 'fr', now)).toBe('Touché par 2 failles. Dernière vérification il y a 3 h.')
    expect(stateSentence(srv({ open_findings: 1, state: { code: 'findings' } }), 'fr', now)).toBe('Touché par 1 faille. Dernière vérification il y a 3 h.')
    expect(stateSentence(srv({ open_findings: 2, state: { code: 'findings' } }), 'en', now)).toBe('Affected by 2 flaws. Last check 3 h ago.')
  })

  test('nothing known, and could not see everything', () => {
    expect(stateSentence(srv(), 'fr', now)).toBe('Aucune faille connue. Dernière vérification il y a 3 h.')
    expect(stateSentence(srv({ state: { code: 'unread' } }), 'fr', now)).toBe("Aucune faille connue, mais Michel n'a pas pu tout voir. Dernière vérification il y a 3 h.")
    expect(stateSentence(srv({ state: { code: 'unread' } }), 'en', now)).toBe('No known flaw, but Michel could not see everything. Last check 3 h ago.')
  })

  test('the states before any check, and while one runs', () => {
    expect(stateSentence(srv({ last_check_at: '', host_key_pinned: false, state: { code: 'key_unconfirmed' } }), 'fr', now))
      .toBe("Pas encore vérifié : confirme d'abord l'empreinte du serveur.")
    expect(stateSentence(srv({ last_check_at: '', state: { code: 'never_checked' } }), 'fr', now)).toBe('Pas encore vérifié.')
    expect(stateSentence(srv({ checking: true, state: { code: 'checking' } }), 'fr', now)).toBe('Michel vérifie ce serveur en ce moment.')
    expect(stateSentence(srv({ active: false, state: { code: 'inactive' } }), 'fr', now)).toBe('Michel ne vérifie plus ce serveur.')
  })

  test('a failed check says why, from the server', () => {
    const t = srv({ state: { code: 'check_failed', text: 'La dernière vérification a échoué : Michel n\'a pas pu joindre le serveur.' } })
    expect(stateSentence(t, 'fr', now)).toBe('La dernière vérification a échoué : Michel n\'a pas pu joindre le serveur.')
    expect(stateSentence(srv({ state: { code: 'check_failed', text: '' } }), 'fr', now)).toBe("La dernière vérification n'est pas allée au bout.")
    expect(stateSentence(null, 'fr', now)).toBe('')
  })

  test('says how many of the flaws are critical or urgent (B9)', () => {
    expect(serverStateLine(srv({ open_findings: 3, critical_open: 1, urgent_open: 0, state: { code: 'findings' } }), 'fr'))
      .toBe('Touché par 3 failles, dont 1 critique.')
    expect(serverStateLine(srv({ open_findings: 3, critical_open: 2, urgent_open: 2, state: { code: 'findings' } }), 'fr'))
      .toBe('Touché par 3 failles, dont 2 urgentes.')
    expect(serverStateLine(srv({ open_findings: 1, critical_open: 1, urgent_open: 1, state: { code: 'findings' } }), 'fr'))
      .toBe('Touché par 1 faille, urgente.')
    expect(serverStateLine(srv({ open_findings: 3, critical_open: 1, urgent_open: 1, state: { code: 'findings' } }), 'en'))
      .toBe('Affected by 3 flaws, 1 of them urgent.')
  })

  test('serverStateLine is the short form of the list', () => {
    expect(serverStateLine(srv({ open_findings: 3, state: { code: 'findings' } }), 'fr')).toBe('Touché par 3 failles.')
  })
})

describe('labels', () => {
  test('kind, environment, interval', () => {
    expect(kindLabel('hds', 'fr')).toBe('HDS (données de santé)')
    expect(kindLabel('vps', 'fr')).toBe('VPS')
    expect(kindLabel('shared', 'fr')).toBe('Mutualisé')
    expect(kindLabel('shared', 'en')).toBe('Shared hosting')
    expect(kindLabel('other', 'fr')).toBe('other')
    expect(envLabel('prod', 'fr')).toBe('Production')
    expect(envLabel('preprod', 'fr')).toBe('Préproduction')
    expect(envLabel('dev', 'en')).toBe('Development')
    expect(intervalLabel('manual', 'fr')).toBe('seulement à la main')
    expect(intervalLabel('24h', 'fr')).toBe('toutes les 24 h')
    expect(intervalLabel('30m', 'en')).toBe('every 30 min')
    expect(intervalLabel('', 'fr')).toBe('toutes les 24 h')
  })

  test('levelLabel names the four server levels in sentences', () => {
    expect(serverLevels).toEqual([0, 1, 2, 3])
    expect(levelLabel(0, 'fr').title).toBe('Signaler')
    expect(levelLabel(1, 'fr').title).toBe('Expliquer et préparer à la demande')
    expect(levelLabel(2, 'fr').title).toBe('Préparer')
    expect(levelLabel(3, 'fr').title).toBe("Appliquer ce que j'ai autorisé")
    expect(levelLabel(3, 'en').title).toBe('Apply what I allowed')
    // Level 3: a fix Michel prepared, even on request, can then run alone.
    expect(levelLabel(3, 'fr').text).toMatch(/même à ta demande/)
    expect(levelLabel(3, 'fr').warn).toMatch(/même à ta demande/)
    expect(levelLabel(3, 'fr').text.endsWith(levelLabel(3, 'fr').warn)).toBe(true)
    expect(levelLabel(3, 'fr').text).toMatch(/seule/)
    for (const n of serverLevels) {
      expect(levelLabel(n, 'fr').text).toMatch(/\.$/)
      expect(levelLabel(n, 'en').text).not.toBe(levelLabel(n, 'fr').text)
    }
    expect(levelLabel(4, 'fr')).toBe(null)
    expect(levelLabel('1', 'fr')).toBe(null)
  })

  test('findingTitle maps PHP-VERSION-UNKNOWN, which has no catalog text', () => {
    expect(findingTitle({ rule: 'PHP-VERSION-UNKNOWN', title: 'PHP-VERSION-UNKNOWN' }, 'fr')).toBe("Michel n'a pas pu lire la version de PHP de ce serveur.")
    expect(findingTitle({ rule: 'expose_php', title: 'PHP annonce sa version' }, 'fr')).toBe('PHP annonce sa version')
    expect(findingTitle({ rule: 'x', title: '', package: 'php' }, 'fr')).toBe('php')
  })
})

describe('headline and order', () => {
  test('touchedServers puts the urgent ones first', () => {
    const a = srv({ id: 'a', open_findings: 5, state: { code: 'findings' } })
    const b = srv({ id: 'b', open_findings: 1, urgent_open: 1, critical_open: 1, state: { code: 'findings' } })
    expect(touchedServers([a, b]).map((t) => t.id)).toEqual(['b', 'a'])
  })

  test('sortFindings: severity first (critical on top), then urgent, then KEV (B2)', () => {
    const list = [
      { id: 'low', severity: 'low' },
      { id: 'crit', severity: 'critical' },
      { id: 'med', severity: 'medium' },
      { id: 'crit-urgent', severity: 'critical', urgent: true },
      { id: 'high-kev', severity: 'high', kev: true },
      { id: 'high', severity: 'high' },
    ]
    expect(sortFindings(list).map((f) => f.id)).toEqual(['crit-urgent', 'crit', 'high-kev', 'high', 'med', 'low'])
    expect(list[0].id).toBe('low')
    expect(sortFindings(null)).toEqual([])
  })

  test('mergeFindings: one card per flaw, listing the PHP runtimes it concerns (B3)', () => {
    const inv = { php: [{ sapi: 'cli', binary: '/usr/local/bin/php' }, { sapi: 'fpm', binary: '/usr/local/sbin/php-fpm' }] }
    const cards = mergeFindings([
      { id: 'f1', rule: 'PHP2SHELL', kind: 'server_package', package: 'php', installed_version: '8.3.35', fixed_versions: ['8.3.36'], sapi: 'fpm', severity: 'critical' },
      { id: 'f2', rule: 'PHP2SHELL', kind: 'server_package', package: 'php', installed_version: '8.3.35', fixed_versions: ['8.3.36'], sapi: 'cli', severity: 'critical' },
      { id: 'f3', rule: 'expose_php', kind: 'server_config', package: 'expose_php', sapi: 'fpm', severity: 'low' },
    ], inv)
    expect(cards.map((c) => c.ids)).toEqual([['f1', 'f2'], ['f3']])
    expect(cards[0].finding.id).toBe('f1')
    expect(cards[0].runtimes).toEqual([{ sapi: 'fpm', binary: '/usr/local/sbin/php-fpm' }, { sapi: 'cli', binary: '/usr/local/bin/php' }])
    expect(cards[1].runtimes).toEqual([{ sapi: 'fpm', binary: '/usr/local/sbin/php-fpm' }])
    expect(mergeFindings([{ id: 'x', rule: 'r', sapi: 'fpm' }], null)[0].runtimes).toEqual([{ sapi: 'fpm', binary: '' }])
  })
})

describe('polling', () => {
  test('serverPollDelay: fast while the script runs, slow while waiting for the user (m2)', () => {
    const a = (state, executor = 'michel') => ({ state, server: { executor } })
    expect(serverPollDelay(a('running'))).toBe(3000)
    expect(serverPollDelay(a('applied'))).toBe(3000)
    expect(serverPollDelay(a('approved'))).toBe(3000)
    expect(serverPollDelay(a('preparing'))).toBe(3000)
    expect(serverPollDelay(a('approved', 'user'))).toBe(30000)
    expect(serverPollDelay(a('unknown'))).toBe(30000)
    expect(serverPollDelay(a('proposed'))).toBe(30000)
    expect(serverPollDelay(a('proven_fixed'))).toBe(0)
    expect(serverPollDelay(a('failed'))).toBe(0)
    expect(serverPollDelay(null)).toBe(0)
  })
})

describe('stepLine', () => {
  test('says each step in one line, in French', () => {
    expect(stepLine({ op: 'backup_file', ok: true, detail: 'done' }, 'fr')).toBe('Copie des fichiers : faite.')
    expect(stepLine({ op: 'set_directive', ok: true, detail: 'done' }, 'fr')).toBe('Modification du réglage : faite.')
    expect(stepLine({ op: 'check_site', ok: false, detail: 'the site does not answer' }, 'fr')).toBe('Vérification du site : le site ne répond pas.')
    expect(stepLine({ op: 'undo', ok: true, detail: 'done' }, 'fr')).toBe('Retour en arrière : fait, le serveur est comme avant.')
    expect(stepLine({ op: 'recollect', ok: true, detail: 'the check no longer sees the problem' }, 'fr'))
      .toBe('Nouvelle vérification du serveur : le problème a disparu.')
    expect(stepLine({ op: 'test_config', ok: false, detail: 'not run' }, 'fr')).toBe('Test de la configuration : pas lancé.')
  })

  test('and in English, with a plain word for what it does not know', () => {
    expect(stepLine({ op: 'reload_service', ok: true, detail: 'done' }, 'en')).toBe('Reload of PHP: done.')
    expect(stepLine({ op: 'package_upgrade', ok: false, detail: 'the upgrade failed; the package may have changed' }, 'en'))
      .toBe('Package upgrade: the upgrade failed, the package may have changed.')
    expect(stepLine({ op: 'mystery', ok: false, detail: 'weird' }, 'en')).toBe('Step: failed.')
    expect(stepLine({ op: 'mystery', ok: true, detail: 'weird' }, 'fr')).toBe('Étape : faite.')
    expect(stepLine(null, 'fr')).toBe('')
  })
})

describe('snapshot and approval', () => {
  const proposal = { hash: 'abc' }
  const attempt = (server, state = 'proposed') => ({ id: 'a1', state, proposal, server })

  test('needsSnapshot reads the server part of the proposal', () => {
    expect(needsSnapshot({ needs_snapshot: true })).toBe(true)
    expect(needsSnapshot(attempt({ needs_snapshot: true }))).toBe(true)
    expect(needsSnapshot({ needs_snapshot: false })).toBe(false)
    expect(needsSnapshot(null)).toBe(false)
  })

  test('canApproveServer is false without the snapshot word', () => {
    expect(canApproveServer(attempt({ needs_snapshot: false }), proposal)).toBe(true)
    expect(canApproveServer(attempt({ needs_snapshot: true, snapshot_done: false }), proposal)).toBe(false)
    expect(canApproveServer(attempt({ needs_snapshot: true, snapshot_done: true }), proposal)).toBe(true)
    expect(canApproveServer(attempt({ needs_snapshot: false }, 'approved'), proposal)).toBe(false)
    expect(canApproveServer(attempt({ needs_snapshot: false }), { hash: '' })).toBe(false)
    expect(canApproveServer(attempt({ needs_snapshot: false }), null)).toBe(false)
    expect(canApproveServer({ id: 'a1', state: 'proposed', proposal }, proposal)).toBe(false)
    expect(canApproveServer(null, proposal)).toBe(false)
    // Scripts the page cannot show are never validated.
    expect(canApproveServer(attempt({ needs_snapshot: false, scripts_unreadable: true }), proposal)).toBe(false)
    expect(isServerAttempt(attempt({}))).toBe(true)
    expect(isServerAttempt({ id: 'a2' })).toBe(false)
  })
})

describe('backupLine', () => {
  test('a copy whose key was lost says so, never "does not match"', () => {
    expect(backupLine({ file: '/var/lib/michel/backups/x/1', state: 'kept' }, 'fr')).toBe('/var/lib/michel/backups/x/1 : copie gardée sur ton ordinateur, chiffrée.')
    expect(backupLine({ file: '/var/lib/michel/backups/x/1', state: 'key_lost' }, 'fr'))
      .toBe('/var/lib/michel/backups/x/1 : clé perdue. La copie de ton ordinateur ne peut plus être ouverte ; celle du serveur reste là.')
    expect(backupLine({ file: 'f', state: 'damaged' }, 'fr')).toBe("f : ne correspond pas. La copie de ton ordinateur a été abîmée ; celle du serveur reste là.")
    expect(backupLine({ file: 'f', state: 'key_lost' }, 'en')).not.toMatch(/match/)
  })
})

describe('routes', () => {
  test('reads and writes the Servers page addresses', () => {
    expect(serversRoute('#/servers')).toEqual({ id: '', finding: '' })
    expect(serversRoute('#/servers/01SRV')).toEqual({ id: '01SRV', finding: '' })
    expect(serversRoute('#/servers/a%20b')).toEqual({ id: 'a b', finding: '' })
    expect(serversRoute('#/serversx')).toBe(null)
    expect(serversRoute('#/fix')).toBe(null)
    expect(serversHash('01SRV')).toBe('#/servers/01SRV')
    expect(serversHash('')).toBe('#/servers')
  })

  test('touchedServers puts the servers with open flaws first, worst first', () => {
    const list = [
      srv({ id: 'a', open_findings: 0 }),
      srv({ id: 'b', open_findings: 1, state: { code: 'findings' } }),
      srv({ id: 'c', open_findings: 3, state: { code: 'findings' } }),
      srv({ id: 'd', state: { code: 'check_failed', text: 'x' } }),
    ]
    expect(touchedServers(list).map((t) => t.id)).toEqual(['c', 'b'])
    expect(touchedServers(null)).toEqual([])
  })
})

describe('restoreNeeded', () => {
  const attempt = (steps, extra = {}) => ({ state: 'failed', server: { needs_snapshot: true, steps, ...extra } })
  test('a package upgrade that failed asks to restore', () => {
    expect(restoreNeeded(attempt([{ op: 'package_upgrade', ok: false, detail: 'failed' }]))).toBe(true)
  })
  test('a site that went down after the upgrade asks to restore', () => {
    expect(restoreNeeded(attempt([{ op: 'package_upgrade', ok: true, detail: '' }, { op: 'check_site', ok: false, detail: 'down' }]))).toBe(true)
  })
  test('a step that did not run does not', () => {
    expect(restoreNeeded(attempt([{ op: 'package_upgrade', ok: false, detail: 'not run' }]))).toBe(false)
  })
  test('a step that went well does not', () => {
    expect(restoreNeeded(attempt([{ op: 'package_upgrade', ok: true, detail: '' }]))).toBe(false)
  })
  test('another step that failed does not', () => {
    expect(restoreNeeded(attempt([{ op: 'config_change', ok: false, detail: 'failed' }]))).toBe(false)
  })
  test('a fix without a snapshot does not', () => {
    expect(restoreNeeded(attempt([{ op: 'package_upgrade', ok: false, detail: 'failed' }], { needs_snapshot: false }))).toBe(false)
  })
  test('another state does not', () => {
    expect(restoreNeeded({ ...attempt([{ op: 'package_upgrade', ok: false, detail: 'failed' }]), state: 'applied' })).toBe(false)
  })
  test('no attempt, or a project fix, does not', () => {
    expect(restoreNeeded(null)).toBe(false)
    expect(restoreNeeded({ state: 'failed' })).toBe(false)
  })
})

describe('the cards of a sheet', () => {
  const cards = [{ key: 'a', finding: { id: 'f1' }, ids: ['f1', 'f2'] }, { key: 'b', finding: { id: 'f3' }, ids: ['f3'] }]
  test('a chosen flaw finds its card, also through a merged runtime', () => {
    expect(cardOfFinding(cards, 'f2').key).toBe('a')
    expect(cardOfFinding(cards, 'f3').key).toBe('b')
    expect(cardOfFinding(cards, 'nope')).toBe(null)
    expect(cardOfFinding(cards, '')).toBe(null)
  })
  test('the last attempt is the newest, whatever its state (GET /fixes is newest first)', () => {
    const fixes = [{ id: 'x', finding: { id: 'other' } }, { id: 'n', state: 'failed', finding: { id: 'f2' } }, { id: 'o', state: 'proven_fixed', finding: { id: 'f1' } }]
    expect(lastAttemptOf(fixes, cards[0]).id).toBe('n')
    expect(lastAttemptOf(fixes, cards[1])).toBe(null)
  })
})

describe('the line of a card', () => {
  const on = (state, extra = {}) => ({ id: 'a', state, server: { target: { id: 'srv', name: 'srv-demo' } }, ...extra })
  test('a final attempt: the path says its state, no second sentence', () => {
    for (const s of ['proven_fixed', 'failed', 'refused', 'inconclusive', 'superseded']) expect(cardLine(on(s), 'fr', 'srv'), s).toBe('')
  })
  test('an attempt under way keeps its line', () => {
    expect(cardLine(on('proposed'), 'fr', 'srv')).toBe('Une correction attend ta validation.')
  })
  test('on its preprod: the line names where it runs', () => {
    const pre = { id: 'p', state: 'proposed', server: { target: { id: 'pre', name: 'srv-pre' } } }
    expect(cardLine(pre, 'fr', 'srv')).toBe('Sur ta préprod srv-pre : Une correction attend ta validation.')
    expect(cardLine({ ...pre, state: 'failed' }, 'fr', 'srv')).toBe('Ce dernier essai a eu lieu sur ta préprod srv-pre.')
  })
})

describe('the sentence under a server proposal', () => {
  test('a flaw that came back is not said corrected', () => {
    expect(doneKey({ state: 'proven_fixed', finding: { status: 'new' } })).toBe('')
    expect(doneKey({ state: 'proven_fixed', finding: { status: 'gone' } })).toBe('srvfix.done.proven_fixed')
  })
  test('the other final states', () => {
    for (const s of ['inconclusive', 'refused', 'superseded']) expect(doneKey({ state: s, finding: {} })).toBe(`srvfix.done.${s}`)
    expect(doneKey({ state: 'failed', cause: '' })).toBe('srvfix.done.failed')
    expect(doneKey({ state: 'failed', cause: 'x' })).toBe('')
    expect(doneKey({ state: 'proposed' })).toBe('')
  })
})

describe('an agent at work is named', () => {
  test('preparing, by origin', () => {
    expect(serverAttemptLine({ state: 'preparing', origin: 'agent' }, 'fr')).toContain("agent d'IA")
    expect(serverAttemptLine({ state: 'preparing', origin: 'agent.auto' }, 'fr')).toContain("agent d'IA")
    expect(serverAttemptLine({ state: 'preparing', origin: 'michel.server' }, 'fr')).toBe('Michel prépare les scripts.')
  })
})

describe('the attempt on a production card', () => {
  const cards = [{ key: 'a', finding: { id: 'f1' }, ids: ['f1', 'f2'] }]
  const pre = (state, extra = {}) => ({ id: 'p', state, created_at: '2026-11-03T10:00:00Z', finding: { id: 'pf', status: 'new' }, server: { prod_finding_id: 'f2' }, ...extra })
  const own = { id: 'o', state: 'failed', created_at: '2026-11-02T10:00:00Z', finding: { id: 'f1' } }
  test('the preprod attempt tried for this flaw shows', () => {
    expect(lastAttemptOf([], cards[0], [pre('proposed')]).id).toBe('p')
    expect(lastAttemptOf([], cards[0], [pre('failed')]).id).toBe('p')
    expect(lastAttemptOf([], cards[0], [{ ...pre('proposed'), server: { prod_finding_id: 'other' } }])).toBe(null)
  })
  test('the newest of the two', () => {
    expect(lastAttemptOf([own], cards[0], [pre('proposed')]).id).toBe('p')
    expect(lastAttemptOf([{ ...own, created_at: '2026-11-04T10:00:00Z' }], cards[0], [pre('proposed')]).id).toBe('o')
  })
  test('proven or gone on the preprod says nothing of the production: never « Vérifiée » here', () => {
    expect(lastAttemptOf([], cards[0], [pre('proven_fixed')])).toBe(null)
    expect(lastAttemptOf([], cards[0], [pre('failed', { finding: { id: 'pf', status: 'gone' } })])).toBe(null)
    expect(lastAttemptOf([], cards[0], [pre('superseded')])).toBe(null)
  })
  test('only the newest preprod attempt counts: an older failure does not come back', () => {
    expect(lastAttemptOf([], cards[0], [pre('proven_fixed'), pre('failed', { id: 'older' })])).toBe(null)
  })
})

describe('who may be offered an agent', () => {
  test('never when the API refuses for health', () => {
    expect(healthServer({ kind: 'hds' })).toBe(true)
    expect(healthServer({ kind: 'vps', classification: 'health' })).toBe(true)
    expect(healthServer({ kind: 'vps', classification: 'sensitive' })).toBe(false)
    expect(healthServer(null)).toBe(false)
    expect(canOfferAgent({ kind: 'vps' }, null)).toBe(true)
    expect(canOfferAgent({ kind: 'hds' }, null)).toBe(false)
    expect(canOfferAgent({ kind: 'vps', classification: 'health' }, null)).toBe(false)
    expect(canOfferAgent({ kind: 'vps' }, { kind: 'hds' })).toBe(false)
  })
})

describe('the title of a verified fix', () => {
  const f = { osv_id: 'expose_php', summary: 'expose_php is risky; advised: Off', package: 'expose_php' }
  test('the flaw is gone from the sheet: the proposal has the translated words', () => {
    expect(guideServerTitle(f, null, { proposal: { summary: 'Régler expose_php sur Off.' } }, 'fr')).toBe('Régler expose_php sur Off.')
  })
  test('the sheet has the flaw: its title', () => {
    expect(guideServerTitle(f, { rule: 'r', title: 'PHP dit sa version' }, { proposal: { summary: 'x' } }, 'fr')).toBe('PHP dit sa version')
  })
  test('nothing else known: the finding', () => {
    expect(guideServerTitle(f, null, null, 'fr')).toBe('expose_php is risky; advised: Off')
  })
})
