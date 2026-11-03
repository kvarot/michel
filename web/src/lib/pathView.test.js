import { describe, expect, test } from 'vitest'
import { canRestart, cameBack, failurePath, isVerified, mergeStep, pathSteps, plainRisk, projectPlan, showsPlan } from './pathView.js'

/** states gives the five states of a path, in order. */
const states = (p) => p.steps.map((s) => s.state)
const finding = (extra = {}) => ({
  id: 'f1', package: 'acme/lib', status: 'pending', kind: 'dependency', ecosystem: 'Packagist',
  manifest_rel_path: 'composer.lock', fixed_versions: ['1.0.5'], osv_id: 'GHSA-abcd-1234-wxyz', ...extra,
})
const attempt = (state, extra = {}) => ({
  id: 'a1', state, project: 'demo', cause: '', branch: '', approved_by: '', proposal: null, messages: null, finding: finding(), ...extra,
})
const project = (extra = {}) => ({ name: 'demo', classification: 'sensitive', fix_level: 1, auto_fix_minor: false, has_test_cmd: true, git_repo: true, ...extra })
const keysOf = (plan) => plan.lines.map((l) => l.key.replace('plan.project.', ''))
const planOf = (f, p) => projectPlan({ finding: f, project: p, level: p.fix_level })

describe('failurePath', () => {
  test('the steps are the five of the spec, in order', () => {
    expect(failurePath({ attempt: null }).steps.map((s) => s.key)).toEqual(['found', 'solution', 'accord', 'fixed', 'verified'])
  })

  // One line per state of the table in the plan, Task 8.
  const clean = { rescan_clean: true }
  const gone = finding({ status: 'gone' })
  const srv = { target: { id: 't' } }
  const table = [
    ['no attempt', null, ['done', 'now', 'todo', 'todo', 'todo'], true, null],
    ['preparing', attempt('preparing'), ['done', 'now', 'todo', 'todo', 'todo'], true, 'preparing'],
    ['proposed', attempt('proposed', { proposal: clean }), ['done', 'done', 'now', 'todo', 'todo'], true, null],
    ['approved', attempt('approved', { approved_by: 'kevin' }), ['done', 'done', 'done', 'now', 'todo'], true, null],
    ['approved by rule', attempt('approved', { approved_by: 'auto' }), ['done', 'done', 'done', 'now', 'todo'], true, 'by_rule'],
    ['running', attempt('running'), ['done', 'done', 'done', 'now', 'todo'], true, null],
    ['applied, project', attempt('applied', { branch: 'michel/fix-1' }), ['done', 'done', 'done', 'done', 'now'], true, 'merge'],
    ['applied, server', attempt('applied', { server: srv }), ['done', 'done', 'done', 'done', 'now'], true, 'checking'],
    ['proven, project', attempt('proven_fixed', { proposal: clean, finding: gone }), ['done', 'done', 'done', 'done', 'done'], false, 'deploy'],
    ['proven, server', attempt('proven_fixed', { finding: gone, server: srv }), ['done', 'done', 'done', 'done', 'done'], false, null],
    ['proven, copy not clean', attempt('proven_fixed', { proposal: { rescan_clean: false }, finding: gone }), ['done', 'done', 'done', 'done', 'stopped'], false, 'copy_not_confirmed'],
    ['proven, came back', attempt('proven_fixed', { proposal: clean }), ['done', 'done', 'done', 'done', 'stopped'], true, 'came_back'],
    ['proven, server, came back', attempt('proven_fixed', { server: srv }), ['done', 'done', 'done', 'done', 'stopped'], true, 'came_back'],
    ['refused', attempt('refused'), ['done', 'done', 'stopped', 'todo', 'todo'], true, 'refused'],
    ['unknown', attempt('unknown'), ['done', 'done', 'done', 'stopped', 'todo'], true, 'unknown'],
    ['superseded', attempt('superseded'), ['done', 'now', 'todo', 'todo', 'todo'], true, 'superseded'],
  ]
  test.each(table)('%s', (_name, a, want, open, note) => {
    const p = failurePath({ attempt: a })
    expect(states(p)).toEqual(want)
    expect(p.open).toBe(open)
    expect(p.note?.key ?? null).toBe(note)
  })

  test('failed stops where it stopped', () => {
    expect(states(failurePath({ attempt: attempt('failed') }))).toEqual(['done', 'stopped', 'todo', 'todo', 'todo'])
    expect(states(failurePath({ attempt: attempt('failed', { proposal: clean }) }))).toEqual(['done', 'done', 'stopped', 'todo', 'todo'])
    expect(states(failurePath({ attempt: attempt('failed', { proposal: clean, approved_by: 'kevin' }) }))).toEqual(['done', 'done', 'done', 'stopped', 'todo'])
  })
  test('failed and inconclusive give the cause of the API', () => {
    const f = failurePath({ attempt: attempt('failed', { cause: 'la tentative a dépassé son temps limite' }) })
    expect(f.note).toEqual({ cause: 'la tentative a dépassé son temps limite' })
    expect(f.open).toBe(true)
    const i = failurePath({ attempt: attempt('inconclusive', { cause: 'la branche est fusionnée' }) })
    expect(states(i)).toEqual(['done', 'done', 'done', 'done', 'stopped'])
    expect(i.note).toEqual({ cause: 'la branche est fusionnée' })
    expect(i.open).toBe(true)
    expect(failurePath({ attempt: attempt('failed') }).note.key).toBe('failed')
    expect(failurePath({ attempt: attempt('inconclusive') }).note.key).toBe('inconclusive')
  })
  test('an exposure that is gone is verified, and closed', () => {
    const p = failurePath({ attempt: null, gone: true })
    expect(states(p)).toEqual(['done', 'done', 'done', 'done', 'done'])
    expect(p.verified).toBe(true)
    expect(p.open).toBe(false)
  })
  test('a project flaw gone without any fix lights nothing Michel did not do', () => {
    const p = failurePath({ attempt: null, vanished: true })
    expect(states(p)).toEqual(['done', 'todo', 'todo', 'todo', 'todo'])
    expect(p.verified).toBe(false)
    expect(p.open).toBe(false)
    expect(p.note.key).toBe('vanished')
  })
  test('an unknown state lights nothing past the flaw', () => {
    expect(states(failurePath({ attempt: attempt('new_state') }))).toEqual(['done', 'stopped', 'todo', 'todo', 'todo'])
    expect(failurePath({ attempt: attempt('new_state') }).verified).toBe(false)
  })
})

describe('verified table', () => {
  const verifiedOf = (a, gone = false) => failurePath({ attempt: a, gone }).verified
  const goneF = finding({ status: 'gone' })
  const clean = { rescan_clean: true }
  test('true only for the three cases of R2', () => {
    expect(verifiedOf(attempt('proven_fixed', { proposal: clean, finding: goneF }))).toBe(true)
    expect(verifiedOf(attempt('proven_fixed', { finding: goneF, server: { target: { id: 't' } } }))).toBe(true)
    expect(verifiedOf(null, true)).toBe(true)
  })
  test('nothing else, not even with a clean copy or a gone finding', () => {
    for (const state of ['preparing', 'proposed', 'approved', 'running', 'applied', 'inconclusive', 'refused', 'failed', 'unknown', 'superseded']) {
      expect(verifiedOf(attempt(state, { proposal: clean, finding: goneF })), state).toBe(false)
      expect(verifiedOf(attempt(state, { proposal: clean, finding: goneF }), true), `${state} gone`).toBe(false)
    }
    expect(verifiedOf(null)).toBe(false)
    expect(verifiedOf(attempt('proven_fixed', { proposal: { rescan_clean: false }, finding: goneF }))).toBe(false)
    expect(verifiedOf(attempt('proven_fixed', { proposal: clean }))).toBe(false)
    expect(isVerified(attempt('proven_fixed', { proposal: clean }))).toBe(false)
  })
})

describe('what can start again', () => {
  const goneF = finding({ status: 'gone' })
  test('cameBack: proven, and seen again', () => {
    expect(cameBack(attempt('proven_fixed'))).toBe(true)
    expect(cameBack(attempt('proven_fixed', { finding: goneF }))).toBe(false)
    expect(cameBack(attempt('applied'))).toBe(false)
    expect(cameBack(null)).toBe(false)
  })
  test('canRestart follows the attempts that went nowhere, and a flaw that came back', () => {
    expect(canRestart(null)).toBe(true)
    for (const s of ['failed', 'refused', 'superseded']) expect(canRestart(attempt(s)), s).toBe(true)
    for (const s of ['preparing', 'proposed', 'approved', 'running', 'applied', 'inconclusive', 'unknown']) expect(canRestart(attempt(s)), s).toBe(false)
    expect(canRestart(attempt('proven_fixed'))).toBe(true)
    expect(canRestart(attempt('proven_fixed', { finding: goneF }))).toBe(false)
  })
  test('the plan is shown before the work ends, not after', () => {
    expect(showsPlan(null)).toBe(true)
    expect(showsPlan(attempt('preparing'))).toBe(true)
    expect(showsPlan(attempt('failed'))).toBe(true)
    for (const s of ['proposed', 'approved', 'applied', 'inconclusive']) expect(showsPlan(attempt(s)), s).toBe(false)
  })
})

describe('project plan tells the truth for each case', () => {
  test('a Composer or npm update with a known version', () => {
    const plan = planOf(finding(), project())
    expect(plan.title).toBe('plan.project.title')
    expect(plan.action).toBe('start')
    expect(keysOf(plan)).toEqual(['copy', 'update', 'tests', 'approval', 'data'])
    expect(plan.lines[1].params).toEqual({ package: 'acme/lib', to: '1.0.5' })
    expect(keysOf(planOf(finding({ ecosystem: 'npm', manifest_rel_path: 'sub/package-lock.json' }), project()))).toContain('update')
  })
  test('the analysis target comes before the first fixed version', () => {
    const plan = planOf(finding({ fixed_versions: ['1.0.5', '2.0.1'], analysis: { upgrade: { target: '2.0.1' } } }), project())
    expect(plan.lines[1].params.to).toBe('2.0.1')
  })
  test('no version named when Michel does not pin it', () => {
    const indirect = planOf(finding({ analysis: { path: { directness: 'transitive' }, upgrade: { target: '1.0.5' } } }), project())
    expect(keysOf(indirect)[1]).toBe('update_any')
    expect(indirect.lines[1].params).toEqual({ package: 'acme/lib' })
    expect(keysOf(planOf(finding({ fixed_versions: ['1.0.5', '2.0.1'] }), project()))[1]).toBe('update_any')
  })
  test('no known version, or no update Michel knows how to run: the agent searches', () => {
    expect(keysOf(planOf(finding({ fixed_versions: [] }), project()))).toEqual(['copy', 'search', 'tests', 'approval', 'data'])
    expect(keysOf(planOf(finding({ ecosystem: 'npm', manifest_rel_path: 'yarn.lock' }), project()))[1]).toBe('search')
  })
  test('no_tests, without tests', () => {
    const keys = keysOf(planOf(finding(), project({ has_test_cmd: false })))
    expect(keys).toContain('no_tests')
    expect(keys).not.toContain('tests')
  })
  test('yarn and pnpm install nothing and run no tests', () => {
    for (const file of ['yarn.lock', 'sub/pnpm-lock.yaml']) {
      const keys = keysOf(planOf(finding({ ecosystem: 'npm', manifest_rel_path: file }), project()))
      expect(keys, file).toContain('no_install')
      expect(keys, file).not.toContain('tests')
    }
  })
  test('a flaw that is not in a lockfile runs no tests either, and says so', () => {
    const keys = keysOf(planOf(finding({ kind: 'code', ecosystem: '', manifest_rel_path: '', fixed_versions: [] }), project()))
    expect(keys).toEqual(['copy', 'search', 'no_install_kind', 'approval', 'data'])
  })
  test('approval_auto, without approval, only at level 3 with the rule', () => {
    const auto = keysOf(planOf(finding(), project({ fix_level: 3, auto_fix_minor: true })))
    expect(auto).toContain('approval_auto')
    expect(auto).not.toContain('approval')
    expect(keysOf(planOf(finding(), project({ fix_level: 3 })))).toContain('approval')
  })
  test('level 2 with auto_fix_minor keeps approval', () => {
    const keys = keysOf(planOf(finding(), project({ fix_level: 2, auto_fix_minor: true })))
    expect(keys).toContain('approval')
    expect(keys).not.toContain('approval_auto')
  })
  test('self_start from level 2 on, only for what the queue takes', () => {
    expect(keysOf(planOf(finding(), project({ fix_level: 1 })))).not.toContain('self_start')
    expect(keysOf(planOf(finding(), project({ fix_level: 2 })))).toContain('self_start')
    expect(keysOf(planOf(finding(), project({ fix_level: 3 })))).toContain('self_start')
    expect(keysOf(planOf(finding({ fixed_versions: [] }), project({ fix_level: 2 })))).not.toContain('self_start')
    expect(keysOf(planOf(finding({ kind: 'code' }), project({ fix_level: 2 })))).not.toContain('self_start')
    expect(keysOf(planOf(finding({ status: 'decided', decision: { action: 'defer' } }), project({ fix_level: 2 })))).not.toContain('self_start')
    const refused = projectPlan({ finding: finding(), project: project({ fix_level: 2 }), attempt: attempt('refused') })
    expect(keysOf(refused)).not.toContain('self_start')
  })
  test('copy and data are always there on a plan that runs', () => {
    for (const lvl of [1, 2, 3]) {
      const keys = keysOf(planOf(finding(), project({ fix_level: lvl })))
      expect(keys[0]).toBe('copy')
      expect(keys.at(-1)).toBe('data')
    }
  })
  test('level defaults to the project', () => {
    expect(keysOf(projectPlan({ finding: finding(), project: project({ fix_level: 0 }) }))).toEqual(['report_only'])
  })
  test('without the project yet, nothing is promised', () => {
    const plan = projectPlan({ finding: finding(), project: null })
    expect(plan.lines).toEqual([])
    expect(plan.action).toBe(null)
  })
})

describe('terminal plans stand alone', () => {
  test.each([
    ['health', project({ classification: 'health' }), 'health'],
    ['report_only', project({ fix_level: 0 }), 'report_only'],
    ['no_git', project({ git_repo: false }), 'no_git'],
  ])('%s', (_n, p, key) => {
    const plan = planOf(finding(), p)
    expect(keysOf(plan)).toEqual([key])
    expect(plan.title).toBe('plan.project.title_michel')
    expect(plan.action).toBe(null)
    expect(plan.why).toBe(key)
  })
  test('no_git, then health, then report_only', () => {
    expect(keysOf(planOf(finding(), project({ git_repo: false, classification: 'health', fix_level: 0 })))).toEqual(['no_git'])
    expect(keysOf(planOf(finding(), project({ classification: 'health', fix_level: 0 })))).toEqual(['health'])
  })
})

describe('no button where nothing can run', () => {
  test('no button at level 0 nor for health', () => {
    expect(planOf(finding(), project({ fix_level: 0 })).action).toBe(null)
    expect(planOf(finding(), project({ classification: 'health' })).action).toBe(null)
    expect(planOf(finding(), project({ classification: 'health', fix_level: 3 })).action).toBe(null)
  })
  test('no button without a Git repository', () => {
    expect(planOf(finding(), project({ git_repo: false })).action).toBe(null)
  })
})

describe('plainRisk', () => {
  const sheet = (impact, extra = {}) => ({ ...finding(), explanation: { impact }, ...extra })
  test('plain risk has no technical id in simple mode', () => {
    const s = sheet('Cette faille (CVE-2024-12345) est grave. Voir GHSA-abcd-1234-wxyz.')
    const out = plainRisk(finding(), s, 'fr', false)
    expect(out).not.toMatch(/CVE|GHSA/)
    expect(out).toContain('Cette faille')
  })
  test('advanced keeps the sentence as it is', () => {
    const text = 'Cette faille (CVE-2024-12345) est grave.'
    expect(plainRisk(finding(), sheet(text), 'fr', true)).toBe(text)
  })
  test('falls back on the summary, then says it has nothing', () => {
    expect(plainRisk(finding({ summary: 'Un résumé.' }), null, 'fr', false)).toBe('Un résumé.')
    expect(plainRisk(finding(), null, 'fr', false)).toBe("Michel n'a pas encore d'explication pour cette faille.")
    expect(plainRisk(finding(), null, 'en', false)).toBe('Michel has no explanation for this flaw yet.')
  })
})

describe('merge', () => {
  test('merge note gives the branch', () => {
    const p = failurePath({ attempt: attempt('applied', { branch: 'michel/fix-01abc' }) })
    expect(p.note).toEqual({ key: 'merge', params: { branch: 'michel/fix-01abc' } })
    const srv = attempt('applied', { branch: '', server: { target: { id: 't' } } })
    expect(failurePath({ attempt: srv }).note.key).toBe('checking')
    expect(mergeStep({ attempt: srv, project: null })).toEqual({ mode: 'none', branch: '', command: '' })
  })
  test('manual merge step gives the command', () => {
    expect(mergeStep({ attempt: attempt('applied', { branch: 'michel/fix-01abc' }), project: project() }))
      .toEqual({ mode: 'manual', branch: 'michel/fix-01abc', command: 'git merge michel/fix-01abc' })
  })
  test('no branch, no command', () => {
    expect(mergeStep({ attempt: attempt('applied'), project: project() }).mode).toBe('none')
    expect(mergeStep({ attempt: null, project: project() }).mode).toBe('none')
    expect(mergeStep({ attempt: attempt('proposed', { branch: 'x' }), project: project() }).mode).toBe('none')
  })
})

describe('pathSteps', () => {
  test('a terminal plan with nothing started has no step in progress', () => {
    const terminal = projectPlan({ finding: finding(), project: project({ fix_level: 0 }) })
    const shown = pathSteps(failurePath({ attempt: null }), terminal, null).map((s) => s.state)
    expect(shown).toEqual(['done', 'todo', 'todo', 'todo', 'todo'])
  })
  test('anything else stays as the path says', () => {
    const running = projectPlan({ finding: finding(), project: project() })
    expect(pathSteps(failurePath({ attempt: null }), running, null).map((s) => s.state)).toEqual(['done', 'now', 'todo', 'todo', 'todo'])
    const a = attempt('proposed')
    const terminal = projectPlan({ finding: finding(), project: project({ fix_level: 0 }) })
    expect(pathSteps(failurePath({ attempt: a }), terminal, a).map((s) => s.state)).toEqual(['done', 'done', 'now', 'todo', 'todo'])
    expect(pathSteps(failurePath({ attempt: null }), null, null).map((s) => s.state)).toEqual(['done', 'now', 'todo', 'todo', 'todo'])
  })
})
