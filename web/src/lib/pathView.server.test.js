import { describe, expect, test } from 'vitest'
import { failurePath, serverPlan, showsPlan } from './pathView.js'
import fr from '../i18n/fr.json'
import en from '../i18n/en.json'

const target = (extra = {}) => ({ id: 't1', name: 'srv-demo', kind: 'vps', classification: 'sensitive', env: 'prod', fix_level: 1, executor: 'user', sudo: 'none', auto_config: false, site_url: 'https://example.test', preprod: null, active: true, ...extra })
const cfg = (extra = {}) => ({ id: 'sf1', kind: 'server_config', rule: 'PHP-INI-1', package: 'expose_php', fixed_versions: [], location: '/etc/php/php.ini:12', status: 'new', ...extra })
const pkg = (extra = {}) => ({ id: 'sf2', kind: 'server_package', ecosystem: 'os', rule: 'USN-1', package: 'openssl', fixed_versions: ['3.0.13'], status: 'new', ...extra })
const keys = (f, t, extra = {}) => serverPlan({ finding: f, target: t, ...extra }).lines.map((l) => l.key.replace('plan.server.', ''))
const srv = { target: { id: 't1', name: 'srv-demo' } }
const rule = { fix_level: 3, auto_config: true, executor: 'michel', sudo: 'nopasswd' }

describe('while an agent prepares, the plan is gone', () => {
  test('a server attempt in preparing shows no plan: it says « sans IA »', () => {
    expect(showsPlan({ state: 'preparing', server: srv, origin: 'agent' })).toBe(false)
    expect(showsPlan({ state: 'preparing', server: srv, origin: 'michel.server' })).toBe(false)
    expect(showsPlan({ state: 'preparing' })).toBe(true)
  })
  test('the path still says nothing changes', () => {
    expect(failurePath({ attempt: { state: 'preparing', server: srv } }).note.key).toBe('preparing_server')
  })
})

describe('the level 3 rule says it runs alone, as root', () => {
  test('neither who nor no_copy, whose promises do not hold', () => {
    const k = keys(cfg(), target(rule))
    expect(k).not.toContain('who')
    expect(k).not.toContain('no_copy')
    expect(k[0]).toBe('who_auto')
    expect(k[1]).toBe('no_copy_auto')
    expect(k).toContain('approval_auto')
  })
  test('with a preprod, who_auto and the preprod line', () => {
    const k = keys(cfg(), target({ ...rule, preprod: { id: 'p', name: 'srv-pre' } }))
    expect(k.slice(0, 2)).toEqual(['who_auto', 'preprod'])
  })
  test('a package always waits: who stays', () => {
    const k = keys(pkg(), target(rule))
    expect(k).toContain('who')
    expect(k).toContain('no_copy')
    expect(k).not.toContain('who_auto')
  })
  test('the words', () => {
    expect(fr['plan.server.who_auto']).toContain('root')
    expect(fr['plan.server.who_auto']).toContain('administrateur')
    expect(fr['plan.server.who_auto']).not.toContain('ne change rien')
    expect(fr['plan.server.no_copy_auto']).not.toContain('Tu peux le lire')
    expect(en['plan.server.who_auto']).toContain('root')
  })
})

describe('PHP’s own flaw has no ready-made fix', () => {
  const upstream = pkg({ ecosystem: 'php-upstream', package: 'php', fixed_versions: ['8.2.30'] })
  test('no simulation, no snapshot, no script', () => {
    const k = keys(upstream, target({ fix_level: 2 }))
    expect(k[0]).toBe('no_ready')
    expect(k).not.toContain('who')
    expect(k).not.toContain('package')
    expect(k).not.toContain('self_prepare')
    expect(k).toContain('agent')
  })
  test('terminal on a health server, which can only refuse', () => {
    const p = serverPlan({ finding: upstream, target: target({ kind: 'hds' }) })
    expect(p.action).toBe(null)
    expect(p.lines.map((l) => l.key)).toEqual(['plan.server.no_ready', 'plan.server.hds'])
  })
  test('a package of the system with a fixed version keeps its plan', () => {
    expect(keys(pkg(), target())).toContain('package')
  })
})

describe('a preprod’s attempts count on the production', () => {
  test('tried: no promise that Michel tries alone', () => {
    expect(keys(cfg(), target({ fix_level: 2 }))).toContain('self_prepare')
    expect(keys(cfg(), target({ fix_level: 2 }), { tried: true })).not.toContain('self_prepare')
  })
  test('a health preprod: no agent, and it is the preprod that is named', () => {
    const t = target({ preprod: { id: 'p', name: 'srv-pre' } })
    const k = keys(cfg(), t, { preprodHealth: true })
    expect(k).toContain('hds_preprod')
    expect(k).not.toContain('agent')
    expect(k).not.toContain('hds')
    const line = serverPlan({ finding: cfg(), target: t, preprodHealth: true }).lines.find((l) => l.key === 'plan.server.hds_preprod')
    expect(line.params).toEqual({ name: 'srv-pre' })
    const none = serverPlan({ finding: pkg({ fixed_versions: [] }), target: t, preprodHealth: true })
    expect(none.action).toBe(null)
    expect(none.lines.map((l) => l.key)).toEqual(['plan.server.no_ready', 'plan.server.hds_preprod'])
  })
})

describe('root is said before the validation', () => {
  test('Michel runs a root script: the next line says so', () => {
    const k = keys(cfg(), target({ executor: 'michel', sudo: 'nopasswd' }))
    expect(k[k.indexOf('approval_michel') + 1]).toBe('root')
    expect(keys(pkg(), target({ executor: 'michel', sudo: 'nopasswd' }))).toContain('root')
    expect(fr['plan.server.root']).toContain('administrateur')
  })
  test('a .user.ini runs as the connection’s user', () => {
    expect(keys(cfg({ location: '/srv/www/.user.ini:3' }), target({ executor: 'michel', sudo: 'none' }))).not.toContain('root')
  })
  test('the user’s script, and the rule, have their own words', () => {
    expect(keys(cfg(), target())).not.toContain('root')
    expect(keys(cfg(), target(rule))).not.toContain('root')
  })
})

describe('a refused fix on a server', () => {
  test('Michel ran nothing; the user may have', () => {
    expect(failurePath({ attempt: { state: 'refused', server: srv } }).note.key).toBe('refused_server')
    expect(fr['path.note.refused_server']).toContain("Michel n'a rien lancé")
    expect(fr['srvfix.done.refused']).toContain("Michel n'a rien lancé")
  })
  test('on a project the note stays', () => {
    expect(failurePath({ attempt: { state: 'refused' } }).note.key).toBe('refused')
  })
})

describe('the French of the plan', () => {
  test('one word for one thing', () => {
    expect(fr['plan.server.checks']).not.toContain('copie')
    expect(fr['plan.server.no_site']).not.toContain('copie')
    expect(fr['plan.server.checks']).toContain('sauvegarde du fichier de réglages')
    expect(fr['plan.server.no_site']).toContain('sauvegarde du fichier de réglages')
  })
  test('each word is explained', () => {
    expect(fr['plan.server.checks']).toContain('relance PHP (le programme qui fait tourner ton site)')
    expect(fr['plan.server.preprod']).toMatch(/^Ce script est d'abord essayé sur ta préprod \{name\} \(ton serveur d'essai\)/)
    expect(fr['plan.server.who']).toContain('un script (une suite de commandes)')
    expect(fr['plan.server.who_auto']).toContain('un script (une suite de commandes)')
    expect(fr['path.note.unknown_server']).toContain("« J'ai vérifié le serveur »")
    expect(fr['plan.server.self_prepare']).toMatch(/^À ce niveau, après une vérification du serveur, Michel essaie aussi de préparer le script de lui-même/)
  })
  test('secrets are recognised, not promised', () => {
    expect(fr['plan.server.agent']).not.toContain('sans les secrets')
    expect(fr['plan.server.agent']).toContain('ce que Michel reconnaît comme secret')
  })
})

describe('a firewall is never confirmed from inside', () => {
  test('expo.how says Michel still sees it open', () => {
    expect(fr['expo.how']).not.toContain('la faire écouter')
    expect(fr['expo.how']).toContain('Michel le verra toujours ouvert')
    expect(fr['expo.how']).not.toMatch(/pare-feu\. Puis lance/)
    expect(en['expo.how']).toContain('will still see it open')
  })
})

describe('a fix of unknown outcome', () => {
  test('nothing promises to prepare anyway: the API refuses', () => {
    expect(fr['servers.unknown.anyway']).toBeUndefined()
    expect(en['servers.unknown.anyway']).toBeUndefined()
    expect(fr['servers.unknown.body']).toContain("« J'ai vérifié le serveur »")
    expect(fr['servers.unknown.body_preprod']).toContain('{name}')
    expect(en['servers.unknown.body']).toContain('"I checked the server"')
  })
})
