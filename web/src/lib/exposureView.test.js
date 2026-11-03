import { describe, expect, test } from 'vitest'
import goEn from '../../../internal/i18n/catalog/en.json'
import goFr from '../../../internal/i18n/catalog/fr.json'
import en from '../i18n/en.json'
import fr from '../i18n/fr.json'
import { closedExposures, exposureColumns, exposureDecisionCheck, exposureDecisionTarget, exposureFindingIds } from './exposureView.js'
import { exposurePath } from './pathView.js'

const target = (extra = {}) => ({ id: 't1', name: 'srv-demo', kind: 'vps', port: 22, ...extra })

/** The two lines GET /targets/{id}/exposure always ends with (targets_exposure.go). */
const always = (cat = goFr) => [
  { key: 'firewall', what: cat['api.exposure.firewall.what'], reason: cat['api.exposure.firewall.reason'] },
  { key: 'udp', what: cat['api.exposure.udp.what'], reason: cat['api.exposure.udp.reason'] },
]
const listeners = { what: goFr['api.exposure.listeners.what'], reason: goFr['collect.unseen.listeners'] }

const service = (port, scope, svc, verdict, extra = {}) => ({ port, addresses: scope === 'open' ? ['0.0.0.0', '::'] : scope === 'server' ? ['127.0.0.1'] : ['10.0.0.5'], scope, service: svc, verdict, finding_id: '', decided_why: '', ...extra })

/** A view as the Go handler answers it after a complete read. */
const read = (services, extra = {}) => ({ read: true, checked_at: '2026-11-02T08:00:00Z', kind: 'vps', services, unseen: always(), closed: [], ...extra })

/** A view as the Go handler answers it when it does not know what listens. */
const notRead = (extra = {}) => ({ read: false, checked_at: '', kind: 'vps', services: [], unseen: [listeners, ...always()], closed: [], ...extra })

const usual = [
  service(22, 'open', 'admin', 'normal'),
  service(80, 'open', 'web', 'normal'),
  service(3306, 'open', 'database', 'close', { finding_id: 'f1' }),
  service(6379, 'server', 'cache', 'close'),
  service(5432, 'private', 'database', 'close'),
  service(8080, 'open', 'other', 'unknown'),
]

const cols = (view, t = target(), lang = 'fr', advanced = false) => exposureColumns(view, t, lang, advanced)
const allText = (c) => JSON.stringify(c)

describe('exposureColumns', () => {
  test('the firewall row is always there', () => {
    const cases = [
      read(usual), notRead(), null, read(usual, { kind: 'shared' }), read(usual, { kind: 'hds' }),
    ]
    for (const v of cases) {
      for (const kind of ['vps', 'shared', 'hds']) {
        const c = cols(v, target({ kind }))
        expect(c.unverified[0], kind).toMatchObject({ name: fr['expo.firewall.name'], note: fr['expo.firewall.note'] })
        expect(c.open.map((r) => r.name)).not.toContain(fr['expo.firewall.name'])
      }
    }
  })
  test('UDP row always there', () => {
    for (const v of [read(usual), notRead(), null]) {
      expect(cols(v).unverified[1]).toMatchObject({ name: fr['expo.udp.name'], note: fr['expo.udp.note'] })
    }
  })
  test('the lines of the API for the firewall and UDP are not said twice, in either language', () => {
    expect(cols(read(usual)).unverified).toHaveLength(2)
    expect(exposureColumns(read(usual, { unseen: always(goEn) }), target(), 'en', false).unverified).toHaveLength(2)
  })
  test('the two lines are known by their key, whatever the API writes', () => {
    const reworded = [{ key: 'firewall', what: 'Autre texte', reason: 'x' }, { key: 'udp', what: 'Encore un autre', reason: 'y' }]
    expect(cols(read(usual, { unseen: reworded })).unverified.map((r) => r.name)).toEqual([fr['expo.firewall.name'], fr['expo.udp.name']])
    // A line without a key is kept: nothing the API says is lost.
    expect(cols(read(usual, { unseen: [{ what: "Le pare-feu de l'hébergeur", reason: 'z' }] })).unverified).toHaveLength(3)
  })
  test('not read says so and keeps the firewall row', () => {
    const c = cols(notRead())
    expect(c.read).toBe(false)
    expect(c.title).toBe("srv-demo : Michel n'a pas encore pu lire quels services attendent qu'on les contacte")
    expect(c.open).toEqual([])
    expect(c.reserved).toEqual([])
    expect(c.empty.open).toBe(fr['expo.col.not_read'])
    expect(c.empty.reserved).toBe(fr['expo.col.not_read'])
    expect(c.unverified.map((r) => r.name)).toEqual([fr['expo.firewall.name'], fr['expo.udp.name'], listeners.what])
  })
  test('zero services while read does not exist: it is not read', () => {
    const c = cols(read([]))
    expect(c.read).toBe(false)
    expect(c.title).toBe("srv-demo : Michel n'a pas encore pu lire quels services attendent qu'on les contacte")
    expect(c.empty.open).toBe(fr['expo.col.not_read'])
  })
  test('the page failing is not « not read »: Michel may have read it', () => {
    const c = exposureColumns(null, target(), 'fr', false, true)
    expect(c.failed).toBe(true)
    expect(c.read).toBe(false)
    expect(c.title).toBe("srv-demo : Michel n'a pas pu afficher cette partie")
    expect(allText(c)).not.toContain(fr['expo.col.not_read'])
    expect(c.unverified.map((r) => r.name)).toEqual([fr['expo.firewall.name'], fr['expo.udp.name']])
    expect(cols(null).failed).toBe(false)
    expect(fr['expo.load_failed']).toBe('Cela ne dit rien de ce qui est ouvert sur le serveur.')
  })
  test('columns follow scope', () => {
    const c = cols(read(usual))
    expect(c.open.map((r) => [r.name, r.tag])).toEqual([
      ["Connexion d'administration", 'normal'], ['Site web', 'normal'], ['Base de données', 'close'], ['Service non reconnu', 'check'],
    ])
    expect(c.reserved.map((r) => [r.name, r.note, r.tag])).toEqual([
      ['Cache', fr['expo.reserved.server'], null], ['Base de données', fr['expo.reserved.private'], null],
    ])
    expect(c.shared).toBe('')
  })
  test('a close verdict is only a word when the service is open to all', () => {
    const c = cols(read([service(3306, 'server', 'database', 'close'), service(6379, 'private', 'cache', 'close')]))
    expect(c.reserved.map((r) => r.tag)).toEqual([null, null])
    expect(c.title).toBe('srv-demo : Michel ne voit aucun service ouvert à tous depuis le serveur')
  })
  test('a normal row shows its note and no word', () => {
    const [admin, web] = cols(read(usual)).open
    expect(web.note).toBe(fr['expo.service.web_note'])
    expect(admin.note).toBe(fr['expo.service.admin_note'])
    expect(web.tag).toBe('normal')
  })
  test('shared: close gives check, no of_close, the sentence is there', () => {
    const v = read([service(3306, 'open', 'database', 'close')], { kind: 'shared' })
    const c = cols(v, target({ kind: 'shared' }))
    expect(c.open[0].tag).toBe('check')
    expect(c.title).toBe('srv-demo : 1 service joignable si aucun pare-feu ne le bloque')
    expect(c.shared).toBe(fr['expo.shared'])
    expect(allText(c)).not.toContain('À fermer')
    expect(c.open[0].note).toBe(fr['expo.shared_note'])
  })
  test('a finding kept on a server that became shared is said, and can still be decided', () => {
    const c = cols(read([service(3306, 'open', 'database', 'close', { finding_id: 'f1' })]), target({ kind: 'shared' }))
    expect(c.open[0]).toMatchObject({ tag: 'check', findingId: 'f1', note: fr['expo.kept'] })
    expect(allText(c)).not.toContain('À fermer')
  })
  test('a finding kept on the port that became the connection one is said', () => {
    const c = cols(read([service(5432, 'open', 'admin', 'normal', { finding_id: 'f1' })]))
    expect(c.open[0]).toMatchObject({ tag: 'check', findingId: 'f1', note: fr['expo.kept'] })
  })
  test('title says firewall whenever something is open', () => {
    expect(cols(read([service(22, 'open', 'admin', 'normal')])).title).toBe('srv-demo : 1 service joignable si aucun pare-feu ne le bloque')
    expect(cols(read(usual)).title).toBe('srv-demo : 4 services joignables si aucun pare-feu ne les bloque, dont 1 à fermer')
    expect(exposureColumns(read(usual), target(), 'en', false).title).toContain('firewall')
    expect(cols(read([service(6379, 'server', 'cache', 'close')])).title).toBe('srv-demo : Michel ne voit aucun service ouvert à tous depuis le serveur')
  })
  test('the sub says where Michel looks from', () => {
    expect(cols(read(usual)).sub).toBe(fr['expo.sub'])
    expect(cols(notRead()).sub).toBe(fr['expo.sub'])
  })
  test('simple mode hides numbers, advanced shows them', () => {
    const simple = cols(read(usual, { closed: [{ port: 11211, service: 'cache', last_seen_open: '2026-10-01T10:00:00Z' }] }))
    for (const r of [...simple.open, ...simple.reserved, ...simple.closed]) expect(r.detail).toBe('')
    // Outside « Que faire ? » and the dialog: the name, the note and the detail hold no number.
    const seen = [...simple.open, ...simple.reserved].map((r) => [r.name, r.note, r.detail])
    expect(allText(seen)).not.toMatch(/3306|8080|6379|0\.0\.0\.0|127\.0\.0\.1/)
    expect(allText(simple.closed)).not.toContain('11211')
    const adv = cols(read(usual, { closed: [{ port: 11211, service: 'cache', last_seen_open: '2026-10-01T10:00:00Z' }] }), target(), 'fr', true)
    expect(adv.open[2].detail).toBe('3306 · 0.0.0.0, ::')
    expect(adv.reserved[0].detail).toBe('6379 · 127.0.0.1')
    expect(adv.closed[0].detail).toBe('11211')
  })
  test('unseen lines join the third column', () => {
    const c = cols(notRead())
    expect(c.unverified[2]).toMatchObject({ name: listeners.what, note: listeners.reason, tag: null, findingId: '' })
  })
  test('decided row keeps its column and says not verified', () => {
    const c = cols(read([service(3306, 'open', 'database', 'close', { finding_id: 'f1', decided_why: 'Bloqué par mon hébergeur.' })]))
    expect(c.open).toHaveLength(1)
    expect(c.open[0].note).toBe("Tu as indiqué : Bloqué par mon hébergeur. Michel ne l'a pas vérifié.")
    expect(c.open[0].decided).toBe(true)
    expect(c.open[0].tag).toBe(null)
    // Still reachable if no firewall blocks it, no longer one to close.
    expect(c.title).toBe('srv-demo : 1 service joignable si aucun pare-feu ne le bloque')
  })
  test('a reason without a full stop still reads as two sentences', () => {
    const c = cols(read([service(3306, 'open', 'database', 'close', { finding_id: 'f1', decided_why: 'voulu' })]))
    expect(c.open[0].note).toBe("Tu as indiqué : voulu. Michel ne l'a pas vérifié.")
  })
  test('a service gone says it is no longer seen, and when it last was', () => {
    const c = cols(read(usual, { closed: [{ port: 3306, service: 'database', last_seen_open: '2026-10-01T10:00:00Z' }] }))
    expect(c.closed[0].text).toBe('Base de données : Michel ne voit plus ce service ouvert à tous.')
    expect(c.closed[0].when).toBe('Dernière fois où Michel a vu ce service ouvert à tous : le 01/10/2026.')
    expect(allText(c.closed)).not.toMatch(/ferm|corrig|vérifi/i)
  })
  test('the date of a service gone is the local day', () => {
    const d = new Date(2026, 9, 2, 0, 30)
    const c = cols(read(usual, { closed: [{ port: 3306, service: 'database', last_seen_open: d.toISOString() }] }))
    expect(c.closed[0].when).toContain('02/10/2026')
  })
  test('a service gone on a server not read now does not say what Michel sees now', () => {
    const c = cols(notRead({ closed: [{ port: 3306, service: '', last_seen_open: '2026-10-01T10:00:00Z' }] }))
    expect(c.closed[0].text).toBe(fr['expo.closed_unread'].replace('{service}', 'Service non reconnu'))
    expect(c.closed[0].text).toContain('Aujourd\'hui, il ne sait pas')
  })
  test('the date of the read is said only when it was read', () => {
    expect(cols(read(usual)).checked).toContain('02/11/2026')
    expect(cols(notRead()).checked).toBe('')
  })
  test('no reassuring word anywhere', () => {
    const banned = /protégé|sécurisé|sûr|\bsafe|\bprotected|\bsecure|rien n'est ouvert|nothing is open/i
    const keys = (cat) => Object.entries(cat).filter(([k]) => k.startsWith('expo.'))
    for (const [k, v] of [...keys(fr), ...keys(en)]) expect(v, k).not.toMatch(banned)
    for (const [k, v] of keys(fr)) {
      expect(v.replace(/À fermer/g, ''), k).not.toMatch(/fermé/i)
    }
    for (const [k, v] of keys(en)) expect(v, k).not.toMatch(/\bclosed\b/i)
    const views = [read(usual), notRead(), read([]), null, read(usual, { closed: [{ port: 3306, service: 'database', last_seen_open: '2026-10-01T10:00:00Z' }] })]
    for (const v of views) {
      for (const lang of ['fr', 'en']) {
        for (const adv of [false, true]) {
          for (const kind of ['vps', 'shared', 'hds']) {
            const text = allText(exposureColumns(v, target({ kind }), lang, adv))
            expect(text).not.toMatch(banned)
            expect(text.replace(/À fermer|à fermer/g, '')).not.toMatch(/fermé/i)
          }
        }
      }
    }
  })
})

describe('the advice of a row', () => {
  const ask = (port) => fr['expo.ask'].replace('{number}', port)
  const closeLines = (port) => [fr['plan.exposure'], fr['expo.how'], ask(port)]
  test('a service to close with a finding: the advice and the number to give', () => {
    const r = cols(read([service(3306, 'open', 'database', 'close', { finding_id: 'f1' })])).open[0]
    expect(r.port).toBe(3306)
    expect(r.advice).toEqual(closeLines(3306))
  })
  test('two bases open can be told apart once the advice is open', () => {
    const [a, b] = cols(read([service(3306, 'open', 'database', 'close', { finding_id: 'f1' }), service(5432, 'open', 'database', 'close', { finding_id: 'f2' })])).open
    expect(a.name).toBe(b.name)
    expect(a.advice.at(-1)).toContain('3306')
    expect(b.advice.at(-1)).toContain('5432')
  })
  test('to close with no finding yet: the advice, and that the button is not there yet', () => {
    const r = cols(read([service(3306, 'open', 'database', 'close')])).open[0]
    expect(r.tag).toBe('close')
    expect(r.findingId).toBe('')
    expect(r.advice).toEqual([...closeLines(3306), fr['expo.how_no_finding']])
  })
  test('a finding kept has the advice too, with no word about the button', () => {
    const r = cols(read([service(3306, 'open', 'database', 'close', { finding_id: 'f1' })]), target({ kind: 'shared' })).open[0]
    expect(r.tag).toBe('check')
    expect(r.advice).toEqual(closeLines(3306))
  })
  test('to check, no finding: one line that names the number', () => {
    const other = cols(read([service(8080, 'open', 'other', 'unknown')])).open[0]
    expect(other.advice).toEqual([fr['expo.check_how'].replace('{number}', 8080)])
    const shared = cols(read([service(3306, 'open', 'database', 'close')]), target({ kind: 'shared' })).open[0]
    expect(shared.advice).toEqual([fr['expo.check_how'].replace('{number}', 3306)])
  })
  test('normal, reserved and decided rows have no advice', () => {
    const c = cols(read([
      service(80, 'open', 'web', 'normal'),
      service(6379, 'server', 'cache', 'close'),
      service(3306, 'open', 'database', 'close', { finding_id: 'f1', decided_why: 'voulu' }),
    ]))
    for (const r of [...c.open, ...c.reserved]) expect(r.advice).toEqual([])
  })
  test('the notes of a service to check do not send the person looking at nothing', () => {
    expect(fr['expo.service.other_note']).toBe('Michel ne sait pas quel programme c\'est.')
    expect(fr['expo.shared_note']).toBe("Il peut être à l'hébergeur ou à un autre client.")
  })
  test('the number is explained in its own sentence, in both languages', () => {
    for (const k of ['expo.ask', 'expo.check_how', 'expo.decision.which']) {
      expect(fr[k], k).toContain("numéro d'accès {number} (le numéro par lequel on joint ce service)")
      expect(en[k], k).toMatch(/ccess number \{number\} \(the number used to reach this service\)/)
    }
  })
  test('the advice does not call it confirmed, and points at the button', () => {
    expect(fr['expo.how']).not.toMatch(/confirmé/)
    expect(en['expo.how']).not.toMatch(/confirms/)
    expect(fr['expo.how']).toContain(fr['expo.decision.open'])
    expect(en['expo.how']).toContain(en['expo.decision.open'])
  })
})

describe('the connection port', () => {
  test('the port Michel connects by is normal', () => {
    const r = cols(read([service(22, 'open', 'admin', 'normal')])).open[0]
    expect(r).toMatchObject({ tag: 'normal', note: fr['expo.service.admin_note'] })
    expect(r.advice).toEqual([])
  })
  test('an administration port Michel does not connect by is to check', () => {
    const r = cols(read([service(22, 'open', 'admin', 'normal'), service(2222, 'open', 'admin', 'normal')]), target({ port: 2222 })).open
    expect(r[0]).toMatchObject({ tag: 'check', note: fr['expo.service.admin_other_note'] })
    expect(r[0].advice).toEqual([fr['expo.check_how'].replace('{number}', 22)])
    expect(r[1]).toMatchObject({ tag: 'normal', note: fr['expo.service.admin_note'] })
  })
  test('with no target, Michel does not guess', () => {
    expect(exposureColumns(read([service(22, 'open', 'admin', 'normal')]), null, 'fr', false).open[0].tag).toBe('normal')
  })
})

describe('changing your mind', () => {
  test('a decided row says how, with the id of its finding', () => {
    const r = cols(read([service(3306, 'open', 'database', 'close', { finding_id: 'f1', decided_why: 'voulu' })])).open[0]
    expect(r.undo).toBe("Pour changer d'avis, tape dans un terminal (la fenêtre où l'on tape des commandes) : michel decide f1 defer --for 1d. Michel t'en reparle demain.")
    expect(exposureColumns(read([service(3306, 'open', 'database', 'close', { finding_id: 'f1', decided_why: 'voulu' })]), target(), 'en', false).open[0].undo).toContain('michel decide f1 defer --for 1d')
  })
  test('a row not decided says nothing of it', () => {
    expect(cols(read(usual)).open.every((r) => r.undo === '')).toBe(true)
  })
  test('the dialog and the help warn before', () => {
    expect(fr['expo.decision.body']).toMatch(/Pour changer d'avis ensuite, il faudra une commande\.$/)
    expect(en['expo.decision.body']).toMatch(/you will need a command\.$/)
    expect(fr['help.exposure.decision']).toMatch(/Pour changer d'avis, il faudra une commande : michel decide\.$/)
    expect(en['help.exposure.decision']).toMatch(/you will need a command: michel decide\.$/)
  })
})

describe('exposureDecisionTarget', () => {
  const f = (extra = {}) => ({ id: 'f1', kind: 'server_exposure', package: '3306', status: 'new', ...extra })
  test('a flaw of a list not read can be decided from its card, and names its number', () => {
    expect(exposureDecisionTarget(f(), 'Base de données')).toEqual({ findingId: 'f1', name: 'Base de données', port: 3306 })
    expect(exposureDecisionTarget(f({ status: 'pending' }), 'x').findingId).toBe('f1')
  })
  test('not when decided, nor for another kind of flaw', () => {
    expect(exposureDecisionTarget(f({ status: 'decided' }), 'x')).toBe(null)
    expect(exposureDecisionTarget(f({ kind: 'server_config' }), 'x')).toBe(null)
  })
  test('a package that is no number names none', () => {
    expect(exposureDecisionTarget(f({ package: 'redis' }), 'x').port).toBe(0)
  })
})

describe('the words around it', () => {
  test('the firewall is defined right under the title, in both languages', () => {
    expect(fr['expo.sub']).toContain("Un pare-feu, c'est le filtre qui décide qui peut s'y connecter.")
    expect(en['expo.sub']).toContain('A firewall is the filter that decides who can connect to it.')
  })
  test('resolved does not call every line a fix (R47)', () => {
    expect(fr['resolved.sub']).not.toMatch(/correction/)
    expect(en['resolved.sub']).not.toMatch(/\bfix\b/)
    expect(fr['resolved.sub']).toContain('les services qu\'il ne voit plus ouverts à tous')
  })
  test('the service never takes a gender it may not have', () => {
    for (const k of ['expo.closed', 'expo.closed_unread', 'expo.closed_date', 'resolved.exposure_date', 'path.step.expo_gone']) {
      expect(fr[k], k).toContain('ce service')
      expect(fr[k], k).not.toMatch(/corrig|vérifi/i)
    }
  })
  test('the flaws above are those Michel noted, not all there may be', () => {
    expect(fr['expo.flaws_above']).toContain('que Michel a relevées')
    expect(en['expo.flaws_above']).toContain('Michel noted')
  })
  test('UDP is tied to « the others », and the cache is said', () => {
    expect(fr['expo.udp.note']).toContain("Les services UDP, l'autre type, n'apparaissent pas ici.")
    expect(en['expo.udp.note']).toContain('other type')
    expect(fr['expo.service.cache_note']).toMatch(/^Une mémoire rapide/)
    expect(en['expo.service.cache_note']).toMatch(/^A fast memory/)
  })
})

describe('the path of an exposure', () => {
  const text = (p) => p.steps.map((s) => fr[`path.step.${s.label || s.key}`])
  test('it never says fixed nor verified', () => {
    for (const args of [{}, { gone: true }, { decided: true }]) {
      const p = exposurePath(args)
      expect(p.verified).toBe(false)
      expect(text(p).join(' ')).not.toMatch(/corrig|vérifi/i)
      for (const l of text(p)) expect(l).toBeTruthy()
    }
  })
  test('the last step reads what Michel sees', () => {
    expect(text(exposurePath({ gone: true })).at(-1)).toBe('Michel ne voit plus ce service ouvert à tous')
    expect(exposurePath({ gone: true }).steps.at(-1).state).toBe('done')
    expect(exposurePath().steps.at(-1).state).toBe('todo')
  })
  test('gone has no step left to come, and names nobody', () => {
    expect(exposurePath({ gone: true }).steps.map((s) => [s.key, s.state])).toEqual([['found', 'done'], ['expo_gone', 'done']])
    expect(exposurePath({ gone: true }).open).toBe(false)
  })
  test('open, it is the person\'s turn; decided, the person has answered', () => {
    expect(exposurePath().steps.map((s) => s.state)).toEqual(['done', 'now', 'todo'])
    expect(exposurePath({ decided: true }).steps.map((s) => [s.key, s.state])).toEqual([['found', 'done'], ['expo_decided', 'done']])
  })
})

describe('exposureFindingIds', () => {
  test('the findings the columns show', () => {
    expect(exposureFindingIds(read(usual))).toEqual(new Set(['f1']))
    expect(exposureFindingIds(notRead()).size).toBe(0)
    expect(exposureFindingIds(null).size).toBe(0)
  })
})

describe('exposureDecisionCheck', () => {
  test('a reason is required, and bounded', () => {
    const now = new Date('2026-11-03T12:00:00Z')
    expect(exposureDecisionCheck('', now)).toEqual({ ok: false, errorKey: 'decision.why_required' })
    expect(exposureDecisionCheck('   ', now).ok).toBe(false)
    expect(exposureDecisionCheck('a'.repeat(1001), now).errorKey).toBe('decision.why_too_long')
    expect(exposureDecisionCheck('voulu', now).ok).toBe(true)
  })
})

describe('closedExposures', () => {
  const servers = [{ id: 'a', name: 'srv-a' }, { id: 'b', name: 'srv-b' }, { id: 'c', name: 'srv-c' }]
  const gone = { port: 3306, service: 'database', last_seen_open: '2026-10-01T10:00:00Z' }
  test('only what a read server no longer shows', () => {
    const views = { a: read(usual, { closed: [gone] }), b: notRead({ closed: [gone] }) }
    expect(closedExposures(servers, views)).toEqual([{ server: { id: 'a', name: 'srv-a' }, service: 'database', at: gone.last_seen_open }])
  })
  test('nothing read, nothing claimed', () => {
    expect(closedExposures(null, null)).toEqual([])
    expect(closedExposures(servers, {})).toEqual([])
  })
})
