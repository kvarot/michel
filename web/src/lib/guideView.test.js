import { describe, expect, test } from 'vitest'
import { dismissGuide, guideFlaw, guideGitQuestion, guideSteps, guideVisible, markGuideRead, readGuide, showGuideAgain } from './guideView.js'
import { keys } from './storage.js'
import en from '../i18n/en.json'
import fr from '../i18n/fr.json'

const scanned = { name: 'demo', last_scan_status: 'ok', git_repo: true, git_answer: 'no' }
const stepOf = (steps, key) => steps.find((s) => s.key === key)
const empty = { projects: [], servers: [], read: false, anyFinding: false }

describe('the first steps', () => {
  test('an empty install starts at step one, and only the current step acts', () => {
    const s = guideSteps(empty)
    expect(s.map((x) => x.key)).toEqual(['add', 'check', 'read'])
    expect(s.map((x) => x.done)).toEqual([false, false, false])
    expect(s.map((x) => x.current)).toEqual([true, false, false])
    expect(s[0].action).toEqual({ label: 'guide.add.action', href: '#/projects' })
    expect(s[1].action).toBeNull()
    expect(s[2].action).toBeNull()
  })
  test('guide resumes from data when storage is empty', () => {
    const state = readGuide(() => '')
    const s = guideSteps({ projects: [scanned], servers: [], read: state.read, anyFinding: true, flawHref: '#/fix/f/1' })
    expect(stepOf(s, 'add').done).toBe(true)
    expect(stepOf(s, 'check').done).toBe(true)
    expect(stepOf(s, 'read').current).toBe(true)
    expect(stepOf(s, 'read').action).toEqual({ label: 'guide.read.action', href: '#/fix/f/1' })
  })
  test('a server read counts as the first check, and a project only added does not', () => {
    const server = { id: 's 1', state: { code: 'clean' } }
    expect(stepOf(guideSteps({ ...empty, servers: [server] }), 'check').done).toBe(true)
    const added = { name: 'demo', last_scan_status: 'never', git_repo: true }
    const s = guideSteps({ ...empty, projects: [added] })
    expect(stepOf(s, 'add').done).toBe(true)
    expect(stepOf(s, 'check').current).toBe(true)
    expect(stepOf(s, 'check').action).toEqual({ label: 'guide.check.action', href: '#/projects' })
  })
  test('a server that was never read leads to its own sheet', () => {
    const s = guideSteps({ ...empty, servers: [{ id: 's 1', state: { code: 'key_unconfirmed' } }] })
    expect(stepOf(s, 'check').done).toBe(false)
    expect(stepOf(s, 'check').action).toEqual({ label: 'guide.check.action_server', href: '#/servers/s%201' })
  })
  test('a failed check is not a first check, and says so', () => {
    const failed = { name: 'demo', last_scan_status: 'failed', last_failure: { code: 'x' } }
    const s = stepOf(guideSteps({ ...empty, projects: [failed] }), 'check')
    expect(s.done).toBe(false)
    expect(s.text).toBe('guide.check.failed')
    expect(s.action).toEqual({ label: 'guide.check.action_failed', href: '#/projects' })
    const srv = stepOf(guideSteps({ ...empty, servers: [{ id: 'a', state: { code: 'check_failed' } }] }), 'check')
    expect(srv.text).toBe('guide.check.failed')
    expect(srv.action).toEqual({ label: 'guide.check.action_failed', href: '#/servers/a' })
  })
  test('a check that runs says so and offers nothing to click', () => {
    const s = stepOf(guideSteps({ ...empty, projects: [{ name: 'demo', last_scan_status: 'never', scanning: true }] }), 'check')
    expect(s.text).toBe('guide.check.running')
    expect(s.action).toBeNull()
    const srv = stepOf(guideSteps({ ...empty, servers: [{ id: 'a', state: { code: 'checking' } }] }), 'check')
    expect(srv.text).toBe('guide.check.running')
    expect(srv.action).toBeNull()
  })
  test('no flaw means step three says so', () => {
    const s = stepOf(guideSteps({ projects: [scanned], servers: [], read: false, anyFinding: false }), 'read')
    expect(s.text).toBe('guide.read.none')
    expect(s.action).toBeNull()
    expect(s.done).toBe(false)
    expect(s.current).toBe(true)
  })
  test('before any check, step three never says there is no flaw', () => {
    expect(stepOf(guideSteps(empty), 'read').text).toBe('guide.read.text')
    const added = { name: 'demo', last_scan_status: 'never' }
    expect(stepOf(guideSteps({ ...empty, projects: [added] }), 'read').text).toBe('guide.read.text')
  })
})

describe('whether the guide shows', () => {
  const allDone = guideSteps({ projects: [scanned], servers: [], read: true, anyFinding: true })
  const open = guideSteps(empty)
  test('done guide disappears', () => {
    expect(allDone.every((s) => s.done)).toBe(true)
    expect(guideVisible(allDone, { dismissed: false, read: true })).toBe(false)
    expect(guideVisible(open, { dismissed: false, read: false })).toBe(true)
  })
  test('dismissed stays dismissed, settings can show it again', () => {
    const state = { dismissed: false, read: false }
    const saved = []
    dismissGuide(state, (k, v) => saved.push([k, v]))
    expect(guideVisible(open, state)).toBe(false)
    expect(saved).toEqual([[keys.guide, JSON.stringify({ dismissed: true, read: false })]])
    // It stays so after a reload.
    expect(readGuide(() => saved[0][1]).dismissed).toBe(true)
    showGuideAgain(state, (k, v) => saved.push([k, v]))
    expect(guideVisible(open, state)).toBe(true)
    // A done guide opens too when it was asked for, for this visit only.
    expect(guideVisible(allDone, state)).toBe(true)
    expect(readGuide(() => saved[1][1])).toEqual({ dismissed: false, read: false })
    dismissGuide(state, () => {})
    expect(guideVisible(allDone, state)).toBe(false)
  })
  test('each new request of the guide counts, so the page can go to it', () => {
    const state = { dismissed: false, read: false }
    showGuideAgain(state, () => {})
    const first = state.asks
    showGuideAgain(state, () => {})
    expect(state.asks).toBeGreaterThan(first)
  })
})

describe('what is kept', () => {
  test('invalid or absent JSON gives false', () => {
    for (const v of ['', '{', 'null', '[]', '"x"', '1', '{"dismissed":"yes","read":1}']) {
      expect(readGuide(() => v), v).toEqual({ dismissed: false, read: false })
    }
    expect(readGuide(() => '{"dismissed":true,"read":true,"other":1}')).toEqual({ dismissed: true, read: true })
  })
  test('storage that throws changes nothing', () => {
    expect(readGuide(() => { throw new Error('blocked') })).toEqual({ dismissed: false, read: false })
    const refuses = () => { throw new Error('blocked') }
    const state = { dismissed: false, read: false }
    markGuideRead(state, refuses)
    expect(state.read).toBe(true)
    dismissGuide(state, refuses)
    expect(state.dismissed).toBe(true)
    showGuideAgain(state, refuses)
    expect(state.dismissed).toBe(false)
  })
  test('a flaw read is written once', () => {
    const state = { dismissed: false, read: false }
    const saved = []
    markGuideRead(state, (k, v) => saved.push([k, v]))
    markGuideRead(state, (k, v) => saved.push([k, v]))
    expect(saved).toEqual([[keys.guide, JSON.stringify({ dismissed: false, read: true })]])
  })
})

describe('the Git question', () => {
  const ask = { name: 'demo', git_repo: true, git_answer: '' }
  const bare = { name: 'demo-bare', git_repo: false, git_answer: '' }
  test('the Git question is asked under step one, never a fourth step', () => {
    expect(guideGitQuestion([ask])).toEqual({ name: 'demo', mode: 'ask' })
    expect(guideSteps({ ...empty, projects: [ask] }).map((s) => s.key)).toEqual(['add', 'check', 'read'])
  })
  test('the Git question never blocks a step', () => {
    const s = guideSteps({ projects: [{ ...ask, last_scan_status: 'ok' }], servers: [], read: true, anyFinding: true })
    expect(s.every((x) => x.done)).toBe(true)
    expect(guideGitQuestion([ask])).not.toBeNull()
    expect(guideVisible(s, { dismissed: false, read: true })).toBe(false)
  })
  test('no Git question without a repository', () => {
    expect(guideGitQuestion([bare])).toEqual({ name: 'demo-bare', mode: 'no_repo' })
    expect(guideGitQuestion([bare, ask])).toEqual({ name: 'demo', mode: 'ask' })
  })
  test('answered once, not asked again, from the data', () => {
    expect(guideGitQuestion([{ ...ask, git_answer: 'unknown' }])).toBeNull()
    expect(guideGitQuestion([{ ...ask, git_answer: 'yes' }, { ...ask, name: 'next' }])).toEqual({ name: 'next', mode: 'ask' })
    expect(guideGitQuestion([])).toBeNull()
    expect(guideGitQuestion(null)).toBeNull()
  })
})

describe('the flaw step three opens', () => {
  test('the first line of the list', () => {
    expect(guideFlaw({ lines: [{ action: { href: '#/fix/a' } }], projects: [], servers: [] })).toEqual({ any: true, href: '#/fix/a' })
  })
  test('without a line, the place that counts it', () => {
    expect(guideFlaw({ lines: [], projects: [{ name: 'demo', open: { high: 1 } }], servers: [] })).toEqual({ any: true, href: '#/projects' })
    expect(guideFlaw({ lines: [], projects: [], servers: [{ id: 'a', open_findings: 2 }] })).toEqual({ any: true, href: '#/servers/a' })
  })
  test('what is deferred is not a flaw to read now', () => {
    expect(guideFlaw({ lines: [], projects: [{ name: 'demo', open: { high: 1 }, decided: { defer: 1 } }], servers: [] }).any).toBe(false)
  })
  test('nothing', () => {
    expect(guideFlaw({ lines: [], projects: [], servers: [] })).toEqual({ any: false, href: '' })
  })
})

describe('the words of the guide and of the empty screens', () => {
  test('they name the buttons as the page does', () => {
    expect(fr['guide.add.action']).toBe(fr['projects.add'])
    expect(en['guide.add.action']).toBe(en['projects.add'])
    expect(fr['empty.projects']).toContain(`« ${fr['project.check']} »`)
    expect(en['empty.projects']).toContain(`"${en['project.check']}"`)
    expect(fr['empty.servers']).toContain(`« ${fr['servers.find']} »`)
    expect(en['empty.servers']).toContain(`"${en['servers.find']}"`)
    expect(fr['guide.add.text']).toContain(`« ${fr['nav.servers']} »`)
    expect(en['guide.add.text']).toContain(`"${en['nav.servers']}"`)
  })
  test('michel serve is said to be what starts Michel, and nothing promises tomorrow', () => {
    expect(fr['help.settings.token']).toContain('la commande qui démarre Michel')
    expect(en['help.settings.token']).toContain('the command that starts Michel')
    expect(fr['expo.decided_undo']).not.toContain('demain')
    expect(en['expo.decided_undo']).not.toContain('tomorrow')
  })
  test('a preprod is named where its settings speak', () => {
    for (const k of ['user', 'michel', 'auto']) {
      expect(fr[`plan.server.approval_${k}_preprod`]).toContain('ta préprod {name}')
      expect(en[`plan.server.approval_${k}_preprod`]).toContain('your preprod {name}')
    }
  })
})
