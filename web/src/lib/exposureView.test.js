import { describe, expect, test } from 'vitest'
import goEn from '../../../internal/i18n/catalog/en.json'
import goFr from '../../../internal/i18n/catalog/fr.json'
import en from '../i18n/en.json'
import fr from '../i18n/fr.json'
import { closedExposures, exposureColumns, exposureDecisionCheck, exposureFindingIds } from './exposureView.js'
import { exposurePath } from './pathView.js'

const target = (extra = {}) => ({ id: 't1', name: 'srv-demo', kind: 'vps', ...extra })

/** The two lines GET /targets/{id}/exposure always ends with (targets_exposure.go). */
const always = (cat = goFr) => [
  { what: cat['api.exposure.firewall.what'], reason: cat['api.exposure.firewall.reason'] },
  { what: cat['api.exposure.udp.what'], reason: cat['api.exposure.udp.reason'] },
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
  test('not read says so and keeps the firewall row', () => {
    const c = cols(notRead())
    expect(c.read).toBe(false)
    expect(c.title).toBe("srv-demo : Michel n'a pas encore pu lire ce qui écoute")
    expect(c.open).toEqual([])
    expect(c.reserved).toEqual([])
    expect(c.empty.open).toBe(fr['expo.col.not_read'])
    expect(c.empty.reserved).toBe(fr['expo.col.not_read'])
    expect(c.unverified.map((r) => r.name)).toEqual([fr['expo.firewall.name'], fr['expo.udp.name'], listeners.what])
  })
  test('zero services while read does not exist: it is not read', () => {
    const c = cols(read([]))
    expect(c.read).toBe(false)
    expect(c.title).toBe("srv-demo : Michel n'a pas encore pu lire ce qui écoute")
    expect(c.empty.open).toBe(fr['expo.col.not_read'])
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
    expect(allText({ a: simple.open, b: simple.reserved })).not.toMatch(/3306|0\.0\.0\.0|127\.0\.0\.1/)
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
    expect(c.closed[0].text).toBe('Base de données : Michel ne le voit plus ouvert à tous.')
    expect(c.closed[0].when).toBe('Vu ouvert pour la dernière fois le 01/10/2026.')
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
    expect(c.closed[0].text).not.toContain('ne le voit plus')
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
    expect(text(exposurePath({ gone: true })).at(-1)).toBe('Michel ne le voit plus ouvert à tous')
    expect(exposurePath({ gone: true }).steps.at(-1).state).toBe('done')
    expect(exposurePath().steps.at(-1).state).toBe('todo')
  })
  test('gone lights nothing the person was not seen doing', () => {
    expect(exposurePath({ gone: true }).steps.map((s) => s.state)).toEqual(['done', 'todo', 'done'])
    expect(exposurePath({ gone: true }).open).toBe(false)
  })
  test('open, it is the person\'s turn; decided, the person has answered', () => {
    expect(exposurePath().steps.map((s) => s.state)).toEqual(['done', 'now', 'todo'])
    expect(exposurePath({ decided: true }).steps.map((s) => s.state)).toEqual(['done', 'done', 'todo'])
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
