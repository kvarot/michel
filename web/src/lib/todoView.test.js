import { describe, expect, test } from 'vitest'
import en from '../i18n/en.json'
import fr from '../i18n/fr.json'
import { buildTodo, serversToRead, toneOf, todoWords, unseenBelow } from './todoView.js'

const now = new Date('2026-11-03T12:00:00Z')

/** A project whose last scan went well, with nothing open unless told. */
function project(name, extra = {}) {
  return { name, last_scan_status: 'ok', open: {}, decided: {}, ...extra }
}

/** A digest where Michel saw everything: one scanned project, a fresh database. */
function digest(extra = {}) {
  return { projects: [project('demo')], exploited: [], failed_scans: 0, osv_fetched_at: '2026-11-03T06:00:00Z', osv_stale: false, ...extra }
}

/** A checked server with nothing open. */
function server(id, extra = {}) {
  return { id, name: `srv-${id}`, active: true, open_findings: 0, urgent_open: 0, critical_open: 0, log_new: 0, state: { code: 'clean', text: '' }, last_check_at: '2026-11-03T06:00:00Z', ...extra }
}

function flaw(id, extra = {}) {
  return { id, kind: 'server_config', rule: `R-${id}`, package: 'php', severity: 'medium', title: `Titre ${id}`, status: 'new', kev: false, urgent: false, ...extra }
}

function build(extra = {}) {
  return buildTodo({ digest: digest(), attempts: [], servers: [], details: {}, lang: 'fr', now, advanced: false, ...extra })
}

function attempt(id, state, extra = {}) {
  return { id, state, project: 'demo', finding: { id: `f-${id}`, package: 'lib', severity: 'high', status: 'pending' }, ...extra }
}

function serverAttempt(id, state, extra = {}) {
  return attempt(id, state, { project: 'srv-a', server: { target: { id: 'a', name: 'srv-a' }, executor: 'michel', steps: [] }, ...extra })
}

/** Every text the result holds, to search it. */
function allText(r) {
  return JSON.stringify(r)
}

describe('order', () => {
  test('urgent first, projects and servers mixed', () => {
    const d = digest({
      projects: [project('demo', { new: [
        { name: 'high-lib', worst_severity: 'high', finding_ids: ['p-high'], what: 'Une faille haute' },
        { name: 'crit-lib', worst_severity: 'critical', finding_ids: ['p-crit'], what: 'Une faille critique' },
        { name: 'low-lib', worst_severity: 'low', finding_ids: ['p-low'], what: 'Une faille faible' },
      ] })],
    })
    const servers = [server('a', { open_findings: 3, urgent_open: 1, critical_open: 1 })]
    const details = { a: { findings: [flaw('s-medium'), flaw('s-urgent', { urgent: true, severity: 'critical' }), flaw('s-high', { severity: 'high' })] } }
    const r = build({ digest: d, servers, details, attempts: [attempt('w', 'proposed')] })
    expect(r.lines.map((l) => l.rank)).toEqual([0, 1, 2, 3, 3, 4, 5])
    expect(r.lines[0].id).toContain('s-urgent')
    expect(r.lines[1].title).toBe('Une faille critique')
    expect(r.lines[3].title).toBe('Une faille haute')
    expect(r.lines[4].title).toBe('Titre s-high')
    expect(r.lines.map((l) => l.word)).toEqual(['Urgent', 'Urgent', 'À valider', 'Important', 'Important', 'À regarder', 'À regarder'])
    expect(r.head).toBe('Bonjour. 7 choses demandent ton attention.')
    expect(r.sub).toBe('1 projet et 1 serveur.')
  })
  test('a single line says one thing', () => {
    const r = build({ servers: [server('a', { log_new: 2 })] })
    expect(r.head).toBe('Bonjour. Une chose demande ton attention.')
    expect(r.sub).toBe('1 serveur.')
  })
})

describe('actions', () => {
  test('one action per line', () => {
    const d = digest({
      exploited: [{ project: 'demo', package: 'bad', finding_id: 'x1', kev_added: '2026-01-01' }],
      projects: [project('demo', { last_scan_status: 'failed', new: [{ name: 'lib', worst_severity: 'medium', finding_ids: ['p1'] }] })],
    })
    const servers = [server('a', { log_new: 1, state: { code: 'check_failed', text: 'x' } }), server('b', { state: { code: 'key_unconfirmed' }, last_check_at: '' })]
    const r = build({ digest: d, servers, attempts: [attempt('p', 'proposed'), attempt('i', 'inconclusive'), serverAttempt('u', 'unknown')] })
    expect(r.lines.length).toBeGreaterThan(5)
    for (const l of r.lines) {
      expect(typeof l.action.label).toBe('string')
      expect(l.action.label).not.toBe('')
      expect(l.action.href).toMatch(/^#\//)
    }
  })
  test('an urgent attempt names its action', () => {
    const r = build({ attempts: [serverAttempt('u', 'unknown')] })
    expect(r.lines[0]).toMatchObject({ rank: 0, word: 'Urgent', tone: 'urgent', action: { label: 'Vérifier le serveur', href: '#/fix/u' } })
  })
  test('a failed package upgrade asks to restore the snapshot, first', () => {
    const steps = [{ op: 'package_upgrade', ok: false, detail: 'the upgrade failed; the package may have changed' }]
    const r = build({ attempts: [serverAttempt('s', 'failed', { server: { target: { id: 'a', name: 'srv-a' }, needs_snapshot: true, steps } })] })
    expect(r.lines[0]).toMatchObject({ rank: 0, word: 'Urgent' })
    expect(r.lines[0].title).toContain('snapshot')
  })
  test('a line for a finding with an attempt opens the attempt, once', () => {
    const d = digest({ projects: [project('demo', { new: [{ name: 'lib', worst_severity: 'critical', finding_ids: ['f-w'], what: 'Une faille' }] })] })
    const r = build({ digest: d, attempts: [attempt('w', 'proposed')] })
    expect(r.lines).toHaveLength(1)
    expect(r.lines[0]).toMatchObject({ rank: 1, action: { href: '#/fix/w' } })
  })
  test('a proposal outranks the high flaw it answers, and takes its line', () => {
    const d = digest({ projects: [project('demo', { new: [{ name: 'lib', worst_severity: 'high', finding_ids: ['f-w'], what: 'Une faille' }] })] })
    const r = build({ digest: d, attempts: [attempt('w', 'proposed')] })
    expect(r.lines).toHaveLength(1)
    expect(r.lines[0]).toMatchObject({ rank: 2, word: 'À valider', tone: 'info', action: { label: 'Lire et valider', href: '#/fix/w' } })
  })
  test('a replaced failure has no line, an unreplaced one has', () => {
    const replaced = { id: 'old', state: 'failed', project: 'demo', finding: { id: 'same', package: 'lib', status: 'pending' } }
    const newest = { id: 'new', state: 'running', project: 'demo', finding: { id: 'same', package: 'lib', status: 'pending' } }
    expect(build({ attempts: [newest, replaced] }).lines).toEqual([])
    const r = build({ attempts: [replaced] })
    expect(r.lines[0]).toMatchObject({ rank: 4, word: 'À regarder', action: { label: 'Comprendre', href: '#/fix/old' } })
  })
  test('a failure or an unproven fix whose project flaw is gone leaves the list', () => {
    const gone = { id: 'x', package: 'lib', status: 'gone' }
    expect(build({ attempts: [attempt('a', 'failed', { finding: gone })] }).lines).toEqual([])
    expect(build({ attempts: [attempt('a', 'inconclusive', { finding: gone })] }).lines).toEqual([])
  })
  test('a server fix left unproven stays on the list even when the flaw is gone', () => {
    const r = build({ attempts: [serverAttempt('s', 'inconclusive', { finding: { id: 'x', package: 'php', status: 'gone' } })] })
    expect(r.lines).toHaveLength(1)
  })
  test('a script the user must run is still to finish', () => {
    const r = build({ attempts: [serverAttempt('s', 'approved', { server: { target: { id: 'a', name: 'srv-a' }, executor: 'user', steps: [] } })] })
    expect(r.lines[0]).toMatchObject({ rank: 2, word: 'À finir', tone: 'info' })
    expect(build({ attempts: [serverAttempt('s', 'approved')] }).lines).toEqual([])
  })
})

describe('exploited flaws', () => {
  const exploited = [
    { project: 'demo', package: 'bad-a', finding_id: 'x1', osv_id: 'CVE-2024-1111', kev_added: '2026-01-01', status: 'new' },
    { project: 'demo', package: 'bad-b', finding_id: 'x2', malicious: true, status: 'decided' },
    { project: 'other', package: 'bad-c', finding_id: 'x3', kev_added: '2026-01-02', status: 'pending' },
  ]
  test('every exploited flaw is an urgent line with an action, even outside the window', () => {
    const r = build({ digest: digest({ exploited, projects: [project('demo'), project('other')] }) })
    const urgent = r.lines.filter((l) => l.rank === 0 && l.word === 'Urgent' && l.tone === 'urgent' && l.action)
    expect(urgent).toHaveLength(3)
    expect(urgent[0].action).toEqual({ label: 'Voir la solution', href: '#/fix?finding=x1' })
    expect(urgent[0].title).toContain('bad-a')
    expect(urgent[0].where).toBe('Projet demo. Des attaques sont déjà connues.')
    expect(urgent[1].title).toContain('malveillant')
  })
  test('a new package line wholly made of an exploited flaw is not said twice', () => {
    const d = digest({ exploited: [exploited[0]], projects: [project('demo', { new: [{ name: 'bad-a', worst_severity: 'low', finding_ids: ['x1'], kev: true }] })] })
    expect(build({ digest: d }).lines).toHaveLength(1)
  })
  test('another flaw of the same package keeps its line, at its own rank', () => {
    const d = digest({ exploited: [exploited[0]], projects: [project('demo', { new: [{ name: 'bad-a', worst_severity: 'high', finding_ids: ['x1', 'x9'], kev: true }] })] })
    const r = build({ digest: d })
    expect(r.lines.map((l) => l.rank)).toEqual([0, 3])
    expect(r.lines[1].action.href).toBe('#/fix?finding=x9')
  })
  test('an exploited package without its digest row is urgent all the same', () => {
    const d = digest({ projects: [project('demo', { new: [{ name: 'bad', worst_severity: 'low', finding_ids: ['y'], malicious: true }] })] })
    expect(build({ digest: d }).lines[0].rank).toBe(0)
  })
  test('an exploited server flaw is urgent, without the alert flag', () => {
    const r = build({ servers: [server('a', { open_findings: 1 })], details: { a: { findings: [flaw('k', { kev: true, severity: 'low' })] } } })
    expect(r.lines[0]).toMatchObject({ rank: 0, word: 'Urgent', action: { label: 'Voir la solution', href: '#/servers/a?finding=k' } })
  })
})

describe('decisions', () => {
  test('a deferred or ignored component has no line until it is due', () => {
    const d = digest({ projects: [project('demo', { new: [
      { name: 'a', worst_severity: 'critical', finding_ids: ['1'], decided: 'ignore' },
      { name: 'b', worst_severity: 'critical', finding_ids: ['2'], decided: 'defer' },
    ], due: [{ package: 'c', finding_id: '3', due_at: '2026-11-20T00:00:00Z', overdue: false, severity: 'critical' }] })] })
    expect(build({ digest: d }).lines).toEqual([])
  })
  test('a component to fix keeps its line', () => {
    const d = digest({ projects: [project('demo', { new: [{ name: 'a', worst_severity: 'critical', finding_ids: ['1'], decided: 'fix' }] })] })
    expect(build({ digest: d }).lines).toHaveLength(1)
  })
  test('a due deferral comes back at the rank of its severity', () => {
    const d = digest({ projects: [project('demo', { due: [{ package: 'c', finding_id: '3', due_at: '2026-11-01T00:00:00Z', overdue: true, severity: 'critical' }] })] })
    expect(build({ digest: d }).lines[0]).toMatchObject({ rank: 1, word: 'Urgent' })
  })
  test('a superseded decision is to review', () => {
    const d = digest({ projects: [project('demo', { superseded: [{ package: 'c', finding_id: '3', severity: 'high', reason: 'new_version' }] })] })
    const r = build({ digest: d })
    expect(r.lines[0]).toMatchObject({ rank: 3 })
    expect(r.lines[0].title).toContain('c')
  })
  test('a decided server finding has no line', () => {
    const r = build({
      servers: [server('a', { open_findings: 1 })],
      details: { a: { findings: [flaw('d', { status: 'decided', severity: 'critical', urgent: true }), flaw('g', { status: 'gone' }), flaw('p', { status: 'pending' })] } },
    })
    expect(r.lines.map((l) => l.id)).toEqual(['server:a:p'])
  })
})

describe('flaws open from before the window', () => {
  test('open findings no line names still make a line, never a reassurance', () => {
    const d = digest({ projects: [project('demo', { open: { critical: 1, high: 2, low: 0 }, decided: { fix: 0, defer: 0, ignore: 4 } })] })
    const r = build({ digest: d })
    expect(r.lines).toHaveLength(1)
    expect(r.lines[0]).toMatchObject({ rank: 1, word: 'Urgent', action: { href: '#/fix' } })
    expect(r.lines[0].title).toContain('3')
    expect(r.head).not.toContain('Rien à faire')
  })
  test('what a line already names is not counted again', () => {
    const d = digest({
      exploited: [{ project: 'demo', package: 'bad', finding_id: 'x', kev_added: '2026-01-01', status: 'new' }],
      projects: [project('demo', {
        open: { critical: 1, high: 1, medium: 1 }, decided: { fix: 0, defer: 1, ignore: 0 },
        new: [{ name: 'lib', worst_severity: 'high', finding_ids: ['n'] }],
      })],
    })
    expect(build({ digest: d }).lines.filter((l) => l.id.startsWith('remaining:'))).toEqual([])
  })
  test('a running fix counts as named', () => {
    const d = digest({ projects: [project('demo', { open: { high: 1 } })] })
    expect(build({ digest: d, attempts: [attempt('r', 'running')] }).lines).toEqual([])
  })
})

describe('never reassures', () => {
  const words = [/va bien/i, /protég/i, /sécuris/i, /\bsafe\b/i, /\bprotected\b/i, /\bsecure/i, /all good/i]
  const cases = {
    'no scan': { digest: digest({ projects: [project('demo', { last_scan_status: 'never' })] }) },
    'nothing watched': { digest: digest({ projects: [] }) },
    'failed scans': { digest: digest({ failed_scans: 1 }) },
    'partial scan': { digest: digest({ projects: [project('demo', { last_scan_status: 'partial' })] }) },
    'no lockfile': { digest: digest({ empty_projects: 1, projects: [project('demo', { last_scan_status: 'empty' })] }) },
    'never checked': { servers: [server('a', { state: { code: 'never_checked' }, last_check_at: '' })] },
    unread: { servers: [server('a', { state: { code: 'unread' } })] },
    'check failed': { servers: [server('a', { state: { code: 'check_failed', text: 'x' } })] },
    'old check': { servers: [server('a', { last_check_at: '2026-10-01T00:00:00Z' })] },
    'stale base': { digest: digest({ osv_stale: true }) },
    'no base': { digest: digest({ osv_fetched_at: '0001-01-01T00:00:00Z' }) },
    'servers not read': { servers: null },
    'fixes not read': { attempts: null },
    'logs not read': { digest: digest({ server_logs: [{ name: 'srv-a', new: 0, gaps: [{ from: 'x' }] }] }) },
  }
  test('an empty list never reassures when something was not seen', () => {
    for (const [name, c] of Object.entries(cases)) {
      for (const lang of ['fr', 'en']) {
        const r = build({ ...c, lang })
        expect(r.unseen.length, name).toBeGreaterThan(0)
        for (const w of words) expect(allText(r), `${name} ${w}`).not.toMatch(w)
      }
    }
  })
  test('the empty head says as far as Michel could see', () => {
    const r = build()
    expect(r.lines).toEqual([])
    expect(r.unseen).toEqual([])
    expect(r.head).toBe("Rien à faire pour l'instant, d'après ce que Michel a pu voir.")
    expect(r.sub).toBe('Michel a regardé : 1 projet.')
    for (const w of words) expect(allText(r)).not.toMatch(w)
  })
  test('what was seen, seen on a server too', () => {
    expect(build({ servers: [server('a')] }).sub).toBe('Michel a regardé : 1 projet et 1 serveur.')
  })
  test('a server with open flaws that could not see everything says so', () => {
    const r = build({ servers: [server('a', { open_findings: 1, state: { code: 'findings' } })], details: { a: { findings: [flaw('p')], unseen: [{ what: 'x', reason: 'y' }] } } })
    expect(r.unseen.map((u) => u.key)).toContain('server_unread')
    expect(allText(r)).not.toContain('"y"')
  })
  test('a server with a missing distribution database could not judge everything', () => {
    const r = build({ servers: [server('a', { open_findings: 1, state: { code: 'findings' } })], details: { a: { findings: [flaw('p')], source_to_enable: 'osv-debian' } } })
    expect(r.unseen.map((u) => u.key)).toContain('server_unread')
  })
  test('the banners keep their own unseen entries out of the list below', () => {
    const r = build({ digest: digest({ failed_scans: 1, osv_stale: true }), servers: [server('a', { state: { code: 'unread' } })] })
    expect(r.unseen.map((u) => u.key).sort()).toEqual(['failed_scans', 'osv_stale', 'server_unread'])
    expect(unseenBelow(r.unseen).map((u) => u.key)).toEqual(['server_unread'])
  })
  test('a failed scan has a line and says where', () => {
    const r = build({ digest: digest({ failed_scans: 1, projects: [project('demo', { last_scan_status: 'interrupted' })] }) })
    expect(r.lines[0]).toMatchObject({ rank: 5, word: 'À regarder', where: 'Projet demo.', action: { href: '#/projects' } })
  })
  test('a server detail that could not be read keeps its counts visible', () => {
    const r = build({ servers: [server('a', { open_findings: 2, urgent_open: 1 }), server('b', { open_findings: 1 })], details: {} })
    expect(r.lines.map((l) => l.rank)).toEqual([0, 4])
    expect(r.lines[0].title).toContain('srv-a')
    expect(r.lines[0].title).toContain('2')
    expect(r.lines[0].action.href).toBe('#/servers/a')
  })
})

describe('texts', () => {
  test('simple mode removes ids', () => {
    const d = digest({ projects: [project('demo', { new: [{ name: 'lib', worst_severity: 'high', finding_ids: ['1'], what: 'La faille CVE-2024-12345 permet de lire des fichiers.' }] })] })
    const servers = [server('a', { open_findings: 2 })]
    const details = { a: { findings: [
      flaw('c', { title: 'Réglage dangereux (CVE-2024-2222)' }),
      flaw('s', { kind: 'server_package', package: 'openssl', title: 'openssl CVE-2024-3333', severity: 'high' }),
    ] } }
    const simple = build({ digest: d, servers, details })
    expect(allText(simple)).not.toMatch(/CVE-|GHSA-/)
    expect(simple.lines.find((l) => l.id === 'server:a:s').title).toBe('Un logiciel installé sur srv-a a une faille connue')
    const advanced = build({ digest: d, servers, details, advanced: true })
    expect(advanced.lines.find((l) => l.id === 'server:a:s').title).toBe('openssl CVE-2024-3333')
    expect(allText(advanced)).toContain('CVE-2024-12345')
  })
  test('an exploited id shows only in advanced mode', () => {
    const d = digest({ exploited: [{ project: 'demo', package: 'bad', finding_id: 'x', osv_id: 'GHSA-abcd-1234-wxyz', kev_added: '2026-01-01' }] })
    expect(allText(build({ digest: d }))).not.toContain('GHSA')
    expect(allText(build({ digest: d, advanced: true }))).toContain('GHSA-abcd-1234-wxyz')
  })
  test('no raw log text', () => {
    const marker = 'MARQUEUR-LOG-SECRET'
    const d = digest({ server_logs: [{ name: 'srv-a', new: 2, top: [{ message: marker, text: marker, sample: marker }] }] })
    const servers = [server('a', { log_new: 2, log_deviations: [marker] })]
    const r = build({ digest: d, servers })
    expect(allText(r)).not.toContain(marker)
    expect(r.lines[0].title).toBe('2 nouvelles erreurs sur srv-a')
    expect(r.lines[0].rank).toBe(5)
  })
  test('more than 20 servers makes one line', () => {
    const servers = Array.from({ length: 23 }, (_, i) => server(`s${i}`, { open_findings: 1 }))
    const details = Object.fromEntries(servers.map((s) => [s.id, { findings: [flaw(`f-${s.id}`)] }]))
    expect(serversToRead(servers)).toHaveLength(20)
    const r = build({ servers, details })
    expect(r.lines).toHaveLength(21)
    const more = r.lines.filter((l) => l.id === 'servers:more')
    expect(more).toHaveLength(1)
    expect(more[0].title).toBe('Et 3 autres serveurs ont des failles ouvertes')
    expect(more[0].action.href).toBe('#/servers')
    expect(r.sub).toBe('23 serveurs.')
  })
  test('the servers read first are the urgent ones, and the rest keeps its weight', () => {
    const plain = Array.from({ length: 21 }, (_, i) => server(`s${i}`, { open_findings: 5 }))
    const hot = server('hot', { open_findings: 1, urgent_open: 1 })
    expect(serversToRead([...plain, hot])[0].id).toBe('hot')
    const urgentRest = Array.from({ length: 22 }, (_, i) => server(`u${i}`, { open_findings: 1, urgent_open: 1 }))
    const r = build({ servers: urgentRest, details: {} })
    expect(r.lines.find((l) => l.id === 'servers:more')).toMatchObject({ rank: 0, word: 'Urgent' })
  })
  test('an inactive server has no line and no count', () => {
    const r = build({ servers: [server('a', { active: false, open_findings: 3, log_new: 3, state: { code: 'inactive' } })] })
    expect(r.lines).toEqual([])
    expect(r.unseen).toEqual([])
  })
  test('exposure line says firewall', () => {
    const r = build({ servers: [server('a', { open_findings: 1 })], details: { a: { findings: [flaw('e', { kind: 'server_exposure', rule: 'exposed_database', severity: 'medium' })] } } })
    expect(r.lines[0].title).toBe('Ta base de données écoute sur toutes les adresses : joignable si aucun pare-feu ne la bloque')
    expect(r.lines[0]).toMatchObject({ rank: 4, word: 'À regarder', action: { label: 'Comprendre', href: '#/servers/a?finding=e' } })
  })
  test('an open cache is not called a database', () => {
    const r = build({ servers: [server('a', { open_findings: 1 })], details: { a: { findings: [flaw('e', { kind: 'server_exposure', rule: 'exposed_cache' })] } } })
    expect(r.lines[0].title).toBe('Un cache (une mémoire rapide utilisée par le site) écoute sur toutes les adresses : joignable si aucun pare-feu ne le bloque')
    expect(r.lines[0].title).not.toContain('base de données')
  })
  test('only a project attempt is told to merge', () => {
    const r = build({ attempts: [serverAttempt('s', 'applied', { branch: 'michel/fix-x' })] })
    expect(allText(r)).not.toMatch(/fusionn/i)
    expect(r.lines[0]).toMatchObject({ rank: 5, word: 'À regarder', title: 'La correction de srv-a est lancée : Michel vérifie le résultat.', action: { label: 'Voir le serveur', href: '#/servers/a?finding=f-s' } })
    const p = build({ attempts: [attempt('p', 'applied')] })
    expect(p.lines[0]).toMatchObject({ rank: 2, word: 'À finir', tone: 'info', title: 'La correction est prête : à toi de la fusionner', action: { label: 'Voir comment finir', href: '#/fix/p' } })
  })
  test('every word has a tone', () => {
    expect(Object.fromEntries(todoWords.map((w) => [w, toneOf(w)]))).toEqual({ urgent: 'urgent', important: 'look', look: 'look', validate: 'info', finish: 'info' })
    for (const w of todoWords) {
      expect(fr[`todo.word.${w}`]).toBeTruthy()
      expect(en[`todo.word.${w}`]).toBeTruthy()
    }
  })
})
