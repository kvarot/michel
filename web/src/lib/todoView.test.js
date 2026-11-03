import { describe, expect, test } from 'vitest'
import en from '../i18n/en.json'
import fr from '../i18n/fr.json'
import { isVerified } from './pathView.js'
import { buildTodo, projectsToRead, resolvedLines, serversToRead, toneOf, todoWords, unseenBelow } from './todoView.js'

const now = new Date('2026-11-03T12:00:00Z')

/** A project as GET /today sends it: every severity and every action counted, zero included. */
function project(name, extra = {}) {
  return {
    name, last_scan_status: 'ok', fix_queued: 0, total: 0, attention: 0, exploited_decided: 0,
    open: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    decided: { fix: 0, defer: 0, ignore: 0 },
    ...extra,
  }
}

/** A decision as the API sends it (decide.Decision.MarshalJSON). */
function decision(action, extra = {}) {
  return {
    id: 'dec', finding_id: 'x', project_id: 'p', action, justification: '', due_at: '', author: 'web', created_at: '2026-11-01T00:00:00Z',
    seen_severity: 'high', seen_fixed_versions: [], seen_kev: false, superseded_at: '', superseded_reason: '', ...extra,
  }
}

/** A finding as GET /projects/{name}/findings sends it (FindingView). */
function view(id, extra = {}) {
  return {
    id, project: 'demo', manifest_rel_path: 'composer.lock', ecosystem: 'Packagist', package: 'lib', osv_id: `GHSA-${id}`, aliases: [],
    severity: 'medium', severity_source: 'osv', cvss: 0, installed_version: '1.2.0', fixed_versions: ['1.2.1'], dep_groups: [], summary: '',
    status: 'new', first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-11-01T00:00:00Z', kind: 'dependency', rule_id: '', location: '',
    source_key: '', malicious: false, kev: false, kev_added: '', epss: 0, epss_percentile: 0, analysis: null, explanation: { what: 'Une phrase.' },
    decision: null, glossary: {}, ...extra,
  }
}

/** What the digest's rows say of a project's findings, as the findings route would send them. */
function rowsOf(p, exploited) {
  const out = new Map()
  for (const row of p.new || []) {
    for (const id of row.finding_ids || []) {
      out.set(id, view(id, {
        project: p.name, package: row.name, severity: row.worst_severity, kev: !!row.kev, malicious: !!row.malicious,
        status: row.decided ? 'decided' : 'new', decision: row.decided ? decision(row.decided) : null,
      }))
    }
  }
  for (const e of exploited.filter((x) => x.project === p.name)) {
    out.set(e.finding_id, view(e.finding_id, { project: p.name, package: e.package, severity: 'high', kev: !!e.kev_added, malicious: !!e.malicious, status: 'new' }))
  }
  for (const s of p.superseded || []) out.set(s.finding_id, view(s.finding_id, { project: p.name, package: s.package, severity: s.severity, status: 'pending' }))
  for (const d of p.due || []) out.set(d.finding_id, view(d.finding_id, { project: p.name, package: d.package, severity: d.severity, status: 'decided', decision: decision('defer', { due_at: d.due_at }) }))
  return [...out.values()]
}

/** Fills open and decided from the rows, as the digest does, unless the test said them. */
function counted(p, exploited) {
  if (Object.values(p.open).some((n) => n > 0)) return p
  const open = { ...p.open }
  const decided = { ...p.decided }
  for (const f of rowsOf(p, exploited)) {
    const action = f.status === 'decided' ? f.decision.action : ''
    if (action) decided[action] += 1
    if (action !== 'ignore') open[f.severity] += 1
  }
  return { ...p, open, decided }
}

/** A digest where Michel saw everything: one scanned project, a fresh database. */
function digest(extra = {}) {
  const d = { projects: [project('demo')], exploited: [], failed_scans: 0, osv_fetched_at: '2026-11-03T06:00:00Z', osv_stale: false, ...extra }
  return { ...d, projects: d.projects.map((p) => counted(p, d.exploited)) }
}

/** A checked server with nothing open. */
function server(id, extra = {}) {
  return { id, name: `srv-${id}`, active: true, open_findings: 0, urgent_open: 0, critical_open: 0, log_new: 0, state: { code: 'clean', text: '' }, last_check_at: '2026-11-03T06:00:00Z', ...extra }
}

function flaw(id, extra = {}) {
  return { id, kind: 'server_config', rule: `R-${id}`, package: 'php', severity: 'medium', title: `Titre ${id}`, status: 'new', kev: false, urgent: false, ...extra }
}

/** buildTodo with the page's reads answered: the findings of a project follow its digest rows unless the test says otherwise. */
function build(extra = {}) {
  const d = extra.digest || digest()
  const findings = Object.fromEntries((d.projects || []).map((p) => [p.name, rowsOf(p, d.exploited || [])]))
  return buildTodo({ digest: d, attempts: [], servers: [], details: {}, findings, lang: 'fr', now, advanced: false, ...extra })
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
    expect(r.lines[1].title).toBe('Une faille touche crit-lib')
    expect(r.lines[3].title).toBe('Une faille touche high-lib')
    expect(r.lines[4].title).toBe('Titre s-high')
    expect(r.lines.map((l) => l.word)).toEqual(['Urgent', 'Urgent', 'À valider', 'Important', 'Important', 'À regarder', 'À regarder'])
    expect(r.head).toBe('Bonjour. 7 choses demandent ton attention.')
    expect(r.sub).toBe('Dans 1 projet et 1 serveur.')
  })
  test('a single line says one thing', () => {
    const r = build({ servers: [server('a', { log_new: 2 })] })
    expect(r.head).toBe('Bonjour. Une chose demande ton attention.')
    expect(r.sub).toBe('Dans 1 serveur.')
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
  const row = (name, severity, ids, extra = {}) => ({ name, worst_severity: severity, finding_ids: ids, what: 'acme/lib 1.2.0 est utilisé, par exemple src/Foo.php:12.', ...extra })
  const open = (counts, decided = {}) => ({ open: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, ...counts }, decided: { fix: 0, defer: 0, ignore: 0, ...decided } })

  test('an old critical flaw has its own line, under its name', () => {
    const d = digest({ projects: [project('demo', open({ critical: 1, high: 2 }, { ignore: 4 }))] })
    const findings = { demo: [view('a', { package: 'old', severity: 'critical' }), view('b', { package: 'other', severity: 'high' }), view('c', { package: 'other', severity: 'high' })] }
    const r = build({ digest: d, findings })
    expect(r.lines.map((l) => [l.rank, l.word, l.title])).toEqual([
      [1, 'Urgent', 'Une faille touche old'],
      [3, 'Important', 'Une faille touche other'],
    ])
    expect(r.lines[0].action).toEqual({ label: 'Voir la solution', href: '#/fix?finding=a' })
    expect(r.head).not.toContain('Rien à faire')
  })
  test('one line per package and severity', () => {
    const d = digest({ projects: [project('demo', open({ high: 2, low: 1 }))] })
    const findings = { demo: [view('a', { severity: 'high' }), view('b', { severity: 'high' }), view('c', { severity: 'low' })] }
    expect(build({ digest: d, findings }).lines.map((l) => l.rank)).toEqual([3, 5])
  })
  test('an ignored flaw on the same row does not hide an old critical', () => {
    const d = digest({ projects: [project('demo', { ...open({ critical: 1, high: 1 }, { ignore: 1 }), new: [row('lib', 'high', ['x', 'y'])] })] })
    const findings = { demo: [
      view('x', { severity: 'high', status: 'decided', decision: decision('ignore') }),
      view('y', { severity: 'high' }),
      view('z', { package: 'old', severity: 'critical' }),
    ] }
    const r = build({ digest: d, findings })
    expect(r.lines.map((l) => [l.rank, l.title])).toEqual([[1, 'Une faille touche old'], [3, 'Une faille touche lib']])
    expect(r.lines[1].action.href).toBe('#/fix?finding=y')
  })
  test('a deferred flaw on the same row does not hide an old critical', () => {
    const d = digest({ projects: [project('demo', { ...open({ critical: 1, high: 2 }, { defer: 1 }), new: [row('lib', 'high', ['x', 'y'])] })] })
    const findings = { demo: [
      view('x', { severity: 'high', status: 'decided', decision: decision('defer', { due_at: '2026-12-20T00:00:00Z' }) }),
      view('y', { severity: 'high' }),
      view('z', { package: 'old', severity: 'critical' }),
    ] }
    expect(build({ digest: d, findings }).lines.map((l) => l.rank)).toEqual([1, 3])
  })
  test('a running fix on a deferred flaw does not hide an old critical', () => {
    const d = digest({ projects: [project('demo', open({ critical: 2 }, { defer: 1 }))] })
    const findings = { demo: [
      view('f-r', { severity: 'critical', status: 'decided', decision: decision('defer', { due_at: '2026-12-20T00:00:00Z' }) }),
      view('z', { package: 'old', severity: 'critical' }),
    ] }
    const r = build({ digest: d, findings, attempts: [attempt('r', 'running')] })
    expect(r.lines.map((l) => l.title)).toEqual(['Une faille touche old'])
  })
  test('an old critical keeps its rank beside a row of the same severity', () => {
    const d = digest({ projects: [project('demo', { ...open({ critical: 2, low: 1 }), new: [row('lib', 'critical', ['a', 'b'])] })] })
    const findings = { demo: [view('a', { severity: 'critical' }), view('b', { severity: 'low' }), view('c', { package: 'old', severity: 'critical' })] }
    const r = build({ digest: d, findings })
    expect(r.lines.map((l) => [l.rank, l.word])).toEqual([[1, 'Urgent'], [1, 'Urgent']])
    expect(r.lines[1].title).toBe('Une faille touche old')
  })
  test('a deferred critical does not raise an old low flaw', () => {
    const d = digest({ projects: [project('demo', open({ critical: 1, low: 1 }, { defer: 1 }))] })
    const findings = { demo: [
      view('c', { severity: 'critical', status: 'decided', decision: decision('defer', { due_at: '2026-12-20T00:00:00Z' }) }),
      view('l', { package: 'old', severity: 'low' }),
    ] }
    const r = build({ digest: d, findings })
    expect(r.lines.map((l) => [l.rank, l.word, l.title])).toEqual([[5, 'À regarder', 'Une faille touche old']])
  })
  test('an exploited flaw is not left in the count of the others', () => {
    const d = digest({
      exploited: [{ project: 'demo', package: 'bad', finding_id: 'x', kev_added: '2026-01-01', status: 'new' }],
      projects: [project('demo', open({ critical: 1, low: 1 }))],
    })
    const findings = { demo: [view('x', { package: 'bad', severity: 'critical', kev: true, kev_added: '2026-01-01' }), view('l', { package: 'old', severity: 'low' })] }
    expect(build({ digest: d, findings }).lines.map((l) => [l.rank, l.word])).toEqual([[0, 'Urgent'], [5, 'À regarder']])
  })
  test('a line named by the digest is not repeated from the findings', () => {
    const d = digest({
      exploited: [{ project: 'demo', package: 'bad', finding_id: 'x', kev_added: '2026-01-01', status: 'new' }],
      projects: [project('demo', {
        ...open({ critical: 1, high: 1, medium: 1 }, { defer: 1 }),
        new: [row('lib', 'high', ['n'])],
        superseded: [{ package: 's', finding_id: 'sup', severity: 'medium', reason: 'new_version' }],
      })],
    })
    const findings = { demo: [
      view('x', { package: 'bad', severity: 'critical', kev: true }),
      view('n', { severity: 'high' }),
      view('sup', { package: 's', severity: 'medium', status: 'pending' }),
    ] }
    expect(build({ digest: d, findings }).lines.map((l) => l.id.split(':')[0])).toEqual(['exploited', 'new', 'superseded'])
  })
  test('a deferred or ignored finding gets no line, a finding to fix keeps one', () => {
    const d = digest({ projects: [project('demo', open({ high: 2 }, { defer: 1, fix: 1, ignore: 1 }))] })
    const findings = { demo: [
      view('i', { severity: 'critical', status: 'decided', decision: decision('ignore') }),
      view('d', { severity: 'critical', status: 'decided', decision: decision('defer') }),
      view('f', { package: 'tofix', severity: 'high', status: 'decided', decision: decision('fix') }),
      view('g', { severity: 'critical', status: 'gone' }),
    ] }
    expect(build({ digest: d, findings }).lines.map((l) => l.title)).toEqual(['Une faille touche tofix'])
  })
  test('a flaw exploited that the digest does not list is urgent all the same', () => {
    const d = digest({ projects: [project('demo', open({ low: 1 }))] })
    const r = build({ digest: d, findings: { demo: [view('k', { severity: 'low', malicious: true })] } })
    expect(r.lines[0]).toMatchObject({ rank: 0, word: 'Urgent' })
  })
  test('the finding of a tool is named after the tool, as the digest does', () => {
    const d = digest({ projects: [project('demo', open({ high: 1 }))] })
    const r = build({ digest: d, findings: { demo: [view('t', { kind: 'code', package: '', severity: 'high', source_key: 'plugin.semgrep', rule_id: 'R1' })] } })
    expect(r.lines[0].title).toBe('Une faille touche semgrep')
  })
  test('a running fix keeps the line of its flaw and opens the fix', () => {
    const d = digest({ projects: [project('demo', open({ high: 1 }))] })
    const r = build({ digest: d, findings: { demo: [view('f-r', { severity: 'high' })] }, attempts: [attempt('r', 'running')] })
    expect(r.lines).toHaveLength(1)
    expect(r.lines[0].action.href).toBe('#/fix/r')
  })
  test('a failed read says so, keeps the count and its worst severity', () => {
    const d = digest({ projects: [project('demo', { ...open({ critical: 1, high: 2, low: 1 }, { defer: 1 }), new: [row('lib', 'high', ['n'])] })] })
    const r = build({ digest: d, findings: { demo: null } })
    expect(r.lines.map((l) => l.id.split(':')[0])).toEqual(['unread', 'new'])
    expect(r.lines[0]).toMatchObject({ rank: 1, word: 'Urgent', action: { label: 'Voir le projet', href: '#/projects' } })
    expect(r.lines[0].title).toBe("Michel n'a pas pu lire le détail de ce projet : au plus 3 failles y restent ouvertes, certaines peut-être déjà listées ici")
  })
  test('nothing open asks for nothing, and says no failure', () => {
    expect(build({ digest: digest(), findings: {} }).lines).toEqual([])
  })
  test('only the projects with something open or a decided fix are read', () => {
    const d = digest({ projects: [
      project('quiet'),
      project('deferred', open({ high: 1 }, { defer: 1 })),
      project('busy', open({ low: 1 })),
      project('tried'),
    ] })
    const attempts = [
      attempt('t', 'failed', { project: 'tried', finding: { id: 'x', package: 'lib', status: 'decided' } }),
      serverAttempt('s', 'failed', { finding: { id: 'y', package: 'php', status: 'decided' } }),
    ]
    expect(projectsToRead(d, attempts).map((p) => p.name)).toEqual(['busy', 'tried'])
    expect(projectsToRead(null, null)).toEqual([])
  })
})

describe('what is under way', () => {
  test('a first scan under way never reads nothing to do', () => {
    for (const lang of ['fr', 'en']) {
      const r = build({ digest: digest({ projects: [project('demo', { last_scan_status: 'running' })] }), lang })
      expect(r.lines).toEqual([])
      expect(r.unseen.map((u) => u.key)).toEqual(['in_progress'])
      expect(r.unseen[0].text).toContain('demo')
      expect(r.head).not.toMatch(/Rien à faire|Nothing to do/)
    }
    const r = build({ digest: digest({ projects: [project('demo', { last_scan_status: 'running' })] }) })
    expect(r.head).toBe("Contrôle en cours : Michel n'a pas encore le résultat.")
    expect(r.unseen[0].text).toBe('Contrôle en cours sur : demo. Le résultat peut changer.')
  })
  test('a first server check under way never reads nothing to do', () => {
    const r = build({ digest: digest({ projects: [] }), servers: [server('a', { state: { code: 'checking' }, last_check_at: '' })] })
    expect(r.unseen.map((u) => u.key)).toEqual(['in_progress'])
    expect(r.unseen[0].text).toContain('srv-a')
    expect(r.head).not.toContain('Rien à faire')
  })
  test('what is to do keeps its head while a check runs', () => {
    const r = build({ servers: [server('a', { log_new: 1 }), server('b', { state: { code: 'checking' } })], details: { a: { findings: [] } } })
    expect(r.head).toBe('Bonjour. Une chose demande ton attention.')
    expect(r.unseen.map((u) => u.key)).toEqual(['in_progress'])
  })
})

describe('a server without open flaws', () => {
  test('its detail is read, within the cap and after the touched ones', () => {
    const list = [server('c1'), server('t', { open_findings: 1, state: { code: 'findings' } }), server('never', { state: { code: 'never_checked' } }), server('off', { active: false })]
    expect(serversToRead(list).map((s) => s.id)).toEqual(['t', 'c1'])
    const many = Array.from({ length: 25 }, (_, i) => server(`c${i}`))
    expect(serversToRead(many)).toHaveLength(20)
    expect(serversToRead(null)).toEqual([])
  })
  test('clean, without its distribution database: Michel says what he could not judge', () => {
    const r = build({ servers: [server('a')], details: { a: { findings: [], source_to_enable: 'osv-debian' } } })
    expect(r.lines).toEqual([])
    expect(r.unseen.map((u) => u.key)).toEqual(['server_unread'])
    expect(r.unseen[0].text).toContain('srv-a')
  })
  test('clean, with something it could not read', () => {
    const r = build({ servers: [server('a')], details: { a: { findings: [], unseen: [{ what: 'x', reason: 'y' }] } } })
    expect(r.unseen.map((u) => u.key)).toEqual(['server_unread'])
  })
  test('a failed read of a clean server is a note, never a line saying 0 flaw', () => {
    const r = build({ servers: [server('a')], details: {} })
    expect(r.lines).toEqual([])
    expect(r.unseen.map((u) => u.key)).toEqual(['server_not_read'])
    expect(r.unseen[0].text).toBe("Michel n'a pas pu vérifier si tout a été contrôlé sur : srv-a.")
  })
  test('past the cap, clean servers stay in the note', () => {
    const servers = Array.from({ length: 22 }, (_, i) => server(`c${i}`))
    const details = Object.fromEntries(serversToRead(servers).map((s) => [s.id, { findings: [] }]))
    const r = build({ servers, details })
    expect(r.lines).toEqual([])
    expect(r.unseen.map((u) => u.key)).toEqual(['server_not_read'])
    expect(r.unseen[0].text).toContain('srv-c21')
    expect(r.unseen[0].text).not.toContain('srv-c3,')
  })
})

describe('a fix whose flaw was decided', () => {
  const decidedServer = { id: 'x', package: 'php', status: 'decided' }
  test('a server fix that failed leaves the list once the flaw is decided', () => {
    expect(build({ attempts: [serverAttempt('s', 'failed', { finding: decidedServer })] }).lines).toEqual([])
    expect(build({ attempts: [serverAttempt('s', 'inconclusive', { finding: decidedServer })] }).lines).toEqual([])
  })
  test('the restore sentence stays whatever was decided', () => {
    const steps = [{ op: 'package_upgrade', ok: false, detail: 'failed' }]
    const r = build({ attempts: [serverAttempt('s', 'failed', { finding: decidedServer, server: { target: { id: 'a', name: 'srv-a' }, needs_snapshot: true, steps } })] })
    expect(r.lines[0]).toMatchObject({ rank: 0, word: 'Urgent' })
  })
  test.each([['ignore'], ['defer']])('a project fix leaves the list when the flaw is on %s', (action) => {
    const a = attempt('p', 'failed', { finding: { id: 'x', package: 'lib', status: 'decided' } })
    const list = [view('x', { status: 'decided', decision: decision(action) })]
    expect(build({ attempts: [a], findings: { demo: list } }).lines).toEqual([])
    expect(build({ attempts: [{ ...a, state: 'inconclusive' }], findings: { demo: list } }).lines).toEqual([])
  })
  test('a project fix stays when the flaw is to fix, or when its finding could not be read', () => {
    const a = attempt('p', 'failed', { finding: { id: 'x', package: 'lib', status: 'decided' } })
    expect(build({ attempts: [a], findings: { demo: [view('x', { status: 'decided', decision: decision('fix') })] } }).lines[0]).toMatchObject({ rank: 4 })
    expect(build({ attempts: [a], findings: { demo: null } }).lines).toHaveLength(1)
  })
})

describe('one line for one flaw', () => {
  test('a superseded decision on an exploited flaw is said once', () => {
    const d = digest({
      exploited: [{ project: 'demo', package: 'bad', finding_id: 'x', kev_added: '2026-01-01', status: 'pending' }],
      projects: [project('demo', { superseded: [{ package: 'bad', finding_id: 'x', severity: 'high', reason: 'new_version' }] })],
    })
    expect(build({ digest: d }).lines.map((l) => l.id)).toEqual(['exploited:x'])
  })
  test('each proposal on a merged line is said', () => {
    const d = digest({ projects: [project('demo', { new: [{ name: 'lib', worst_severity: 'high', finding_ids: ['f-a', 'f-b'] }] })] })
    const r = build({ digest: d, attempts: [attempt('a', 'proposed'), attempt('b', 'proposed')] })
    expect(r.lines.map((l) => l.action.href)).toEqual(['#/fix/a', '#/fix/b'])
    expect(r.head).toBe('Bonjour. 2 choses demandent ton attention.')
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
    'scan running': { digest: digest({ projects: [project('demo', { last_scan_status: 'running' })] }) },
    'server checking': { servers: [server('a', { state: { code: 'checking' } })] },
    'clean server not read': { servers: [server('a')] },
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
    expect(build({ servers: [server('a')], details: { a: { findings: [] } } }).sub).toBe('Michel a regardé : 1 projet et 1 serveur.')
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
    expect(simple.lines.find((l) => l.id.startsWith('new:')).title).toBe('Une faille touche lib')
  })
  test('the title of a line is not the whole explanation, nor a file of the code', () => {
    const what = "acme/lib 1.2.0 est utilisé à 2 endroits de ton code, par exemple src/Foo.php:12. L'avis dit : « Path traversal in acme/lib »"
    const d = digest({ projects: [project('demo', { new: [{ name: 'acme/lib', worst_severity: 'critical', finding_ids: ['1'], what }] })] })
    const simple = build({ digest: d })
    expect(simple.lines[0].title).toBe('Une faille touche acme/lib')
    expect(allText(simple)).not.toContain('Foo.php')
    expect(allText(simple)).not.toContain('Path traversal')
    expect(build({ digest: d, advanced: true }).lines[0].title).toBe(what)
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
    expect(r.sub).toBe('Dans 23 serveurs.')
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

/** An attempt as GET /fixes sends it (AttemptView, list form). */
function proven(id, extra = {}) {
  return {
    id, finding: { id: `f-${id}`, manifest_rel_path: 'composer.lock', ecosystem: 'Packagist', package: 'lib', osv_id: 'GHSA-aaaa-bbbb-cccc', severity: 'high', installed_version: '1.2.0', fixed_versions: ['1.2.1'], summary: '', status: 'gone' },
    project: 'demo', origin: 'user', state: 'proven_fixed', cause: '', cause_detail: '', approved_by: 'web', branch: 'michel/fix-1',
    created_at: '2026-10-30T08:00:00Z', updated_at: '2026-11-02T09:30:00Z',
    proposal: { id: 'p', summary: '', files: [], tests_status: 'passed', rescan_clean: true, risk: 1, hash: 'h', steps_server: [], commands: [], from_version: '1.2.0', to_version: '1.2.1', created_at: '2026-10-31T00:00:00Z' },
    messages: null, ...extra,
  }
}

/** The server part of an attempt (ServerAttemptView, the fields the page reads). */
function onServer(extra = {}) {
  return { project: 'srv-demo', proposal: null, server: { target: { id: 'srv1', name: 'srv-demo' }, executor: 'michel' }, ...extra }
}

describe('resolvedLines', () => {
  test('only verified attempts are listed as verified', () => {
    const lines = resolvedLines([
      proven('a'),
      proven('b', { proposal: { rescan_clean: false } }),
      proven('c', { state: 'inconclusive' }),
      proven('d', { state: 'applied' }),
      proven('e', onServer()),
      proven('f', onServer({ state: 'inconclusive' })),
    ], [], 'fr')
    const byId = Object.fromEntries(lines.map((l) => [l.href, l]))
    expect(lines).toHaveLength(3)
    expect(lines.filter((l) => l.verified)).toHaveLength(2)
    expect(byId['#/fix/b'].verified).toBe(false)
    expect(byId['#/fix/a'].verified).toBe(true)
    expect(isVerified(proven('c', { state: 'proven_fixed', proposal: null }))).toBe(false)
  })

  test('date from updated_at, newest first', () => {
    const lines = resolvedLines([
      proven('a', { updated_at: '2026-10-01T10:00:00Z' }),
      proven('b', { updated_at: '2026-11-02T09:30:00Z', created_at: '2026-01-01T00:00:00Z' }),
    ], [], 'fr')
    expect(lines.map((l) => l.href)).toEqual(['#/fix/b', '#/fix/a'])
    expect(lines[0].at).toBe('02/11/2026')
    expect(resolvedLines([proven('a')], [], 'en')[0].at).toBe('2026-11-02')
  })

  test('a project says to deploy, a server does not', () => {
    const [p] = resolvedLines([proven('a')], [], 'fr')
    const [s] = resolvedLines([proven('e', onServer())], [], 'fr')
    expect(p.where).toBe('Projet demo.')
    expect(p.deploy).toBe(true)
    expect(s.where).toBe('Serveur srv-demo.')
    expect(s.deploy).toBe(false)
    expect(s.href).toBe('#/servers/srv1?finding=f-e')
  })

  test('a gone exposure is a verified line', () => {
    const lines = resolvedLines([], [{ id: 'x1', server: { id: 'srv1', name: 'srv-demo' }, rule: 'exposed_cache', at: '2026-11-01T00:00:00Z' }], 'fr')
    expect(lines).toHaveLength(1)
    expect(lines[0].verified).toBe(true)
    expect(lines[0].title).toContain('toutes les adresses')
  })

  test('empty list says what it means', () => {
    expect(resolvedLines([], [], 'fr')).toEqual([])
    expect(resolvedLines(null, null, 'fr')).toEqual([])
    expect(fr['empty.resolved']).toMatch(/confirmé sa correction/)
    expect(en['empty.resolved']).toBeTruthy()
    expect(fr['resolved.deploy']).toMatch(/déployer/)
  })
})
