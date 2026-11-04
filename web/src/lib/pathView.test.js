import { describe, expect, test } from 'vitest'
import { canPrepareServer, canRestart, cameBack, chatNoStart, failurePath, isGone, isVerified, mergeStep, pathSteps, plainRisk, projectPlan, rescanKey, serverPlan, showsPlan } from './pathView.js'
import fr from '../i18n/fr.json'
import en from '../i18n/en.json'

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
const openPush = (extra = {}) => ({ provider: 'github', display: 'github.com/demo/app', branch: 'michel/fix-01abc', merge_url: '', pushed_at: '', pushed: false, can_push: true, ...extra })
const sentPush = (extra = {}) => openPush({ merge_url: 'https://github.com/demo/app/pull/new/michel/fix-01abc', pushed_at: '2026-11-04T10:00:00Z', pushed: true, ...extra })
const gitOf = (extra = {}) => ({ repo: 'ok', answer: 'yes', attached: true, changed: false, suggested: 'yes', reason: 'known', provider: 'github', display: 'github.com/demo/app',
  host: 'github.com', remote_id: 'r1', had_credential: false, can_attach: true, update: null, ...extra })
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
    ['applied, project', attempt('applied', { branch: 'michel/fix-1' }), ['done', 'done', 'done', 'now', 'todo'], true, 'merge'],
    ['applied, server', attempt('applied', { server: srv }), ['done', 'done', 'done', 'done', 'now'], true, 'checking'],
    ['proven, project', attempt('proven_fixed', { proposal: clean, finding: gone }), ['done', 'done', 'done', 'done', 'done'], false, 'deploy'],
    ['proven, server', attempt('proven_fixed', { finding: gone, server: srv }), ['done', 'done', 'done', 'done', 'done'], false, null],
    ['proven, copy not clean', attempt('proven_fixed', { proposal: { rescan_clean: false }, finding: gone }), ['done', 'done', 'done', 'done', 'stopped'], false, 'copy_not_confirmed'],
    ['proven, came back', attempt('proven_fixed', { proposal: clean }), ['done', 'done', 'done', 'done', 'stopped'], true, 'came_back'],
    ['proven, server, came back', attempt('proven_fixed', { server: srv }), ['done', 'done', 'done', 'done', 'stopped'], true, 'came_back_server'],
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
    expect(states(i)).toEqual(['done', 'done', 'done', 'stopped', 'todo'])
    expect(i.note).toEqual({ cause: 'la branche est fusionnée' })
    expect(i.open).toBe(true)
    expect(failurePath({ attempt: attempt('failed') }).note.key).toBe('failed')
    expect(failurePath({ attempt: attempt('inconclusive') }).note.key).toBe('inconclusive')
  })
  test('an exposure that is gone is finished, and never verified', () => {
    const p = failurePath({ attempt: null, gone: true })
    expect(states(p)).toEqual(['done', 'done'])
    expect(p.verified).toBe(false)
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
  test('true only for the two proofs of R2, an exposure gone is none (R47)', () => {
    expect(verifiedOf(attempt('proven_fixed', { proposal: clean, finding: goneF }))).toBe(true)
    expect(verifiedOf(attempt('proven_fixed', { finding: goneF, server: { target: { id: 't' } } }))).toBe(true)
    expect(verifiedOf(null, true)).toBe(false)
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

// A code flaw has no ecosystem (plugin/run.go): a rescan of the copy cannot run
// on it (service.go rescan returns an error), so rescan_clean is always false.
describe('a flaw that cannot be rechecked on the copy', () => {
  const codeF = (extra = {}) => finding({ kind: undefined, ecosystem: '', package: '', manifest_rel_path: '', fixed_versions: [], ...extra })
  const notClean = { rescan_clean: false }
  test('proven and still gone: verified, no red step, the path says the copy was not checked', () => {
    const a = attempt('proven_fixed', { proposal: notClean, finding: codeF({ status: 'gone' }) })
    expect(isVerified(a)).toBe(true)
    const p = failurePath({ attempt: a })
    expect(states(p)).toEqual(['done', 'done', 'done', 'done', 'done'])
    expect(p.verified).toBe(true)
    expect(p.note.key).toBe('deploy_unchecked')
  })
  test('a finding with no status is a flaw Michel knows nothing of, not a flaw of the code', () => {
    // The API joins the finding: a finding gone from the store comes empty.
    const empty = attempt('proposed', { proposal: notClean, finding: { id: 'f1', ecosystem: '', status: '' } })
    expect(rescanKey(empty)).toBe('fix.proposal.rescan_dirty')
    const noStatus = attempt('proposed', { proposal: notClean, finding: { id: 'f1', ecosystem: '' } })
    expect(rescanKey(noStatus)).toBe('fix.proposal.rescan_dirty')
    expect(rescanKey(attempt('proposed', { proposal: notClean, finding: codeF() }))).toBe('fix.proposal.rescan_unknown')
  })
  test('proven and seen again: not verified', () => {
    const a = attempt('proven_fixed', { proposal: notClean, finding: codeF({ status: 'new' }) })
    expect(isVerified(a)).toBe(false)
    expect(failurePath({ attempt: a }).note.key).toBe('came_back')
  })
  test('proposed: the path says Michel could not check it', () => {
    const p = failurePath({ attempt: attempt('proposed', { proposal: notClean, finding: codeF() }) })
    expect(states(p)).toEqual(['done', 'done', 'now', 'todo', 'todo'])
    expect(p.note.key).toBe('not_checked')
  })
  test('nothing before the proof verifies it', () => {
    for (const s of ['preparing', 'proposed', 'approved', 'running', 'applied', 'inconclusive', 'refused', 'failed', 'unknown', 'superseded']) {
      expect(isVerified(attempt(s, { proposal: notClean, finding: codeF({ status: 'gone' }) })), s).toBe(false)
    }
  })
  test('where a rescan could run, a dirty copy still stops at Vérifiée', () => {
    const a = attempt('proven_fixed', { proposal: notClean, finding: finding({ status: 'gone' }) })
    expect(isVerified(a)).toBe(false)
    expect(states(failurePath({ attempt: a }))).toEqual(['done', 'done', 'done', 'done', 'stopped'])
    expect(failurePath({ attempt: attempt('proposed', { proposal: notClean }) }).note).toBe(null)
  })
  test('a finding the attempt view could not load is not taken for a code flaw', () => {
    // AttemptView of a finding that is gone from the store (internal/api/fix.go).
    const lost = { id: 'x', manifest_rel_path: '', ecosystem: '', package: '', osv_id: '', severity: '', installed_version: '', fixed_versions: [], summary: '', status: '' }
    expect(isVerified(attempt('proven_fixed', { proposal: notClean, finding: lost }))).toBe(false)
  })
  test('the proposal says it, never that the flaw is still there', () => {
    expect(rescanKey(attempt('proposed', { proposal: notClean, finding: codeF() }))).toBe('fix.proposal.rescan_unknown')
    expect(rescanKey(attempt('proposed', { proposal: notClean }))).toBe('fix.proposal.rescan_dirty')
    expect(rescanKey(attempt('proposed', { proposal: { rescan_clean: true } }))).toBe('fix.proposal.rescan_clean')
    // A new scan that did not confirm is not a scan that saw the flaw.
    expect(fr['fix.proposal.rescan_dirty']).not.toContain('toujours là')
    expect(en['fix.proposal.rescan_dirty']).not.toContain('still there')
    expect(fr['fix.proposal.rescan_dirty']).toContain('ne peut pas confirmer')
    expect(fr['fix.proposal.rescan_unknown']).not.toContain('toujours là')
    expect(en['fix.proposal.rescan_unknown']).not.toContain('still there')
    expect(fr['path.note.not_checked']).not.toContain('toujours là')
    expect(en['path.note.not_checked']).not.toContain('still there')
  })
})

describe('applied, on a project', () => {
  test('Corrigée is not done: the step reads ready, not yet in the code', () => {
    const p = failurePath({ attempt: attempt('applied', { branch: 'michel/fix-1' }) })
    const fixed = p.steps.find((s) => s.key === 'fixed')
    expect(fixed).toEqual({ key: 'fixed', state: 'now', label: 'fixed_ready' })
    expect(p.steps.find((s) => s.key === 'verified').state).toBe('todo')
    expect(fr['path.step.fixed_ready']).toBe('Prête, pas encore dans ton code')
    expect(en['path.step.fixed_ready']).toBe('Ready, not yet in your code')
  })
  test('the step is Corrigée, done, once proven', () => {
    const p = failurePath({ attempt: attempt('proven_fixed', { proposal: { rescan_clean: true }, finding: finding({ status: 'gone' }) }) })
    expect(p.steps.find((s) => s.key === 'fixed')).toEqual({ key: 'fixed', state: 'done' })
  })
  test('a server has no code to wait for: its step stays as it was', () => {
    const p = failurePath({ attempt: attempt('applied', { server: { target: { id: 't' } } }) })
    expect(p.steps.find((s) => s.key === 'fixed')).toEqual({ key: 'fixed', state: 'done' })
    expect(p.steps.find((s) => s.key === 'verified').state).toBe('now')
  })
})

describe('a flaw already gone offers nothing to start', () => {
  const goneF = finding({ status: 'gone' })
  test('isGone reads the sheet first', () => {
    expect(isGone(goneF, null)).toBe(true)
    expect(isGone(finding(), { status: 'gone' })).toBe(true)
    expect(isGone(goneF, { status: 'new' })).toBe(false)
    expect(isGone(finding(), null)).toBe(false)
    expect(isGone(null, null)).toBe(false)
  })
  test('no restart and no plan, with or without an attempt', () => {
    for (const a of [null, attempt('failed', { finding: goneF }), attempt('refused', { finding: goneF }), attempt('superseded', { finding: goneF })]) {
      expect(canRestart(a, true), a?.state).toBe(false)
      expect(showsPlan(a, true), a?.state).toBe(false)
    }
  })
  test('without gone, nothing changes', () => {
    for (const a of [null, attempt('failed'), attempt('refused'), attempt('superseded')]) {
      expect(canRestart(a, false), a?.state).toBe(true)
      expect(showsPlan(a, false), a?.state).toBe(true)
    }
  })
  test.each([
    ['failed', attempt('failed', { cause: 'x' }), ['done', 'stopped', 'todo', 'todo', 'todo']],
    ['failed after the proposal', attempt('failed', { proposal: { rescan_clean: true } }), ['done', 'done', 'stopped', 'todo', 'todo']],
    ['refused', attempt('refused'), ['done', 'done', 'stopped', 'todo', 'todo']],
    ['superseded', attempt('superseded'), ['done', 'todo', 'todo', 'todo', 'todo']],
  ])('the attempt keeps its own path, %s', (_n, a, want) => {
    const p = failurePath({ attempt: a, vanished: true })
    expect(states(p)).toEqual(want)
    expect(p.note).toEqual({ key: 'vanished_after' })
    expect(p.open).toBe(false)
    expect(p.verified).toBe(false)
  })
  test('an attempt under way or proven is not touched', () => {
    expect(failurePath({ attempt: attempt('preparing'), vanished: true }).note.key).toBe('preparing')
    expect(failurePath({ attempt: attempt('applied', { branch: 'b' }), vanished: true }).note.key).toBe('merge')
    const proven = attempt('proven_fixed', { proposal: { rescan_clean: true }, finding: goneF })
    expect(failurePath({ attempt: proven, vanished: true }).note.key).toBe('deploy')
  })
})

describe('the start of the advanced conversation (R14)', () => {
  test('at level 0 advanced mode keeps it: the guide has no button', () => {
    expect(chatNoStart({ guided: true, project: project({ fix_level: 0 }) })).toBe(false)
  })
  test('elsewhere the guide holds the button', () => {
    expect(chatNoStart({ guided: true, project: project() })).toBe(true)
    expect(chatNoStart({ guided: true, project: null })).toBe(true)
  })
  test('a project no fix can run on keeps no start, even at level 0', () => {
    expect(chatNoStart({ guided: true, project: project({ fix_level: 0, classification: 'health' }) })).toBe(true)
    expect(chatNoStart({ guided: true, project: project({ fix_level: 0, git_repo: false }) })).toBe(true)
  })
  test('a flaw already gone keeps no start, even at level 0', () => {
    expect(chatNoStart({ guided: true, project: project({ fix_level: 0 }), gone: true })).toBe(true)
  })
  test('without a guide, the conversation keeps its start', () => {
    expect(chatNoStart({ guided: false, project: project() })).toBe(false)
  })
})

describe('the words of the plan (F1, F6, F7, F9, FR)', () => {
  test('key files stay out, a key written in the code does not', () => {
    // workcopy/copy.go excludes .env*, *.pem, *.key, id_*: no other key file.
    expect(fr['plan.project.copy']).toContain('sans tes fichiers .env ni tes clés au format .pem ou .key')
    expect(fr['plan.project.copy']).toContain('une clé ou un mot de passe enregistré ailleurs dans ton projet (dans ton code, un fichier de réglages, une clé d\'un autre format) reste dans la copie')
    expect(fr['plan.project.copy']).not.toContain('fichiers de clés')
    expect(en['plan.project.copy']).toContain('your keys in .pem or .key format')
    expect(en['plan.project.copy']).toContain('stays in the copy')
    expect(fr['plan.project.data']).toContain('y compris une clé enregistrée dans ces fichiers')
    expect(en['plan.project.data']).toContain('including a key saved in these files')
  })
  test('the update is tried: a lockfile or a setting can make Michel refuse it', () => {
    for (const k of ['update', 'update_near', 'update_any']) {
      expect(fr['plan.project.' + k]).toContain('Michel essaie de mettre à jour')
      expect(en['plan.project.' + k]).toContain('Michel tries to update')
    }
  })
  test('the key on the page: hidden here, not from the agent', () => {
    expect(fr['fix.secret_hint']).toBe("Michel cache cette clé secrète sur cette page. Si elle est écrite dans ton code, l'agent a pu la lire. La vraie valeur reste dans ton projet.")
    expect(en['fix.secret_hint']).toContain('the agent may have read it')
  })
  test('the fix that cannot be told apart names the button of the server', () => {
    for (const k of ['path.note.unknown', 'fix.line.unknown']) {
      expect(fr[k]).toContain("Regarde si ton site marche normalement, puis clique sur « J'ai vérifié le serveur ».")
      expect(fr[k]).toContain(fr['srvfix.unknown.resolve'])
      expect(en[k]).toContain(en['srvfix.unknown.resolve'])
    }
  })
  test('a flaw of the code seen in the project, never checked on the copy', () => {
    expect(fr['path.note.deploy_unchecked']).toContain("Michel l'a vu dans ton projet (il ne pouvait pas le contrôler avant). Pense à publier")
    expect(en['path.note.deploy_unchecked']).toContain('Michel saw it in your project (he could not check it before). Remember to publish')
  })
  test('the branch is found with a command, not in a named editor (B4)', () => {
    expect(fr['git.manual.lead']).toContain('git branch --show-current')
    expect(fr['git.manual.lead']).not.toContain('PhpStorm')
    expect(en['git.manual.lead']).toContain('git branch --show-current')
    expect(en['git.manual.lead']).not.toContain('PhpStorm')
  })
  test('self_start names the consent', () => {
    expect(fr['plan.project.self_start']).toContain('une fois ton accord donné pour ce projet')
    expect(en['plan.project.self_start']).toContain('once you have agreed for this project')
  })
  test('tests are something Michel tries', () => {
    expect(fr['plan.project.tests']).toContain('essaie')
    expect(en['plan.project.tests']).toContain('tries')
  })
  test('approval_auto does not read as a closed list', () => {
    expect(fr['plan.project.approval_auto']).toContain('toutes les conditions, dont :')
    expect(en['plan.project.approval_auto']).toContain('all the conditions, including:')
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
    expect(keysOf(plan)).toEqual(['copy', 'update_near', 'tests', 'approval', 'data'])
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
    expect(keysOf(planOf(finding({ ecosystem: 'npm', manifest_rel_path: 'yarn.lock', fixed_versions: [] }), project()))[1]).toBe('search')
  })
  test('a version is known but Michel does not run the update: the agent does it', () => {
    for (const file of ['yarn.lock', 'pnpm-lock.yaml']) {
      expect(keysOf(planOf(finding({ ecosystem: 'npm', manifest_rel_path: file }), project()))[1], file).toBe('update_agent')
    }
  })
  test('Composer may resolve higher than the version named, npm pins it', () => {
    const composer = planOf(finding(), project())
    expect(keysOf(composer)[1]).toBe('update_near')
    expect(composer.lines[1].params).toEqual({ package: 'acme/lib', to: '1.0.5' })
    expect(fr['plan.project.update_near']).toContain('ou une version proche plus récente')
    const npm = planOf(finding({ ecosystem: 'npm', manifest_rel_path: 'package-lock.json' }), project())
    expect(keysOf(npm)[1]).toBe('update')
  })
  test('approval_auto only where the rule could apply: without tests, approval', () => {
    const rule = project({ fix_level: 3, auto_fix_minor: true })
    expect(keysOf(planOf(finding(), rule))).toContain('approval_auto')
    const noTests = keysOf(planOf(finding(), project({ fix_level: 3, auto_fix_minor: true, has_test_cmd: false })))
    expect(noTests).toContain('approval')
    expect(noTests).not.toContain('approval_auto')
    const yarn = keysOf(planOf(finding({ ecosystem: 'npm', manifest_rel_path: 'yarn.lock' }), rule))
    expect(yarn).toContain('approval')
    const code = keysOf(planOf(finding({ kind: 'code', ecosystem: '', manifest_rel_path: '', fixed_versions: [] }), rule))
    expect(code).toContain('approval')
    expect(code).not.toContain('approval_auto')
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
    // B10: the summary is the advisory's own title, often English: the simple mode says so.
    expect(plainRisk(finding({ summary: 'Cross-domain cookie leakage' }), null, 'fr', false)).toBe("Le texte d'origine, souvent en anglais, dit : « Cross-domain cookie leakage »")
    expect(plainRisk(finding({ summary: 'Cross-domain cookie leakage' }), null, 'en', false)).toBe('The original text says: "Cross-domain cookie leakage"')
    // I10: no technical id in the simple mode, even in the original text.
    const withId = plainRisk(finding({ summary: 'CVE-2024-1234: cookie leak' }), null, 'fr', false)
    expect(withId).not.toContain('CVE-2024-1234')
    expect(withId).toMatch(/cookie leak/i)
    expect(plainRisk(finding({ summary: 'CVE-2024-1234' }), null, 'fr', false)).toBe(fr['path.means_none'])
    expect(plainRisk(finding({ summary: 'Cross-domain cookie leakage' }), null, 'fr', true)).toBe('Cross-domain cookie leakage')
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
    expect(mergeStep({ attempt: srv, project: null })).toEqual({ mode: 'none', branch: '', command: '', push: null, link: null, update: null, attach: false })
    // The same note in both modes: the path does not depend on the attachment.
    const sent = attempt('applied', { branch: 'michel/fix-01abc', push: sentPush() })
    expect(failurePath({ attempt: sent }).note).toEqual({ key: 'merge', params: { branch: 'michel/fix-01abc' } })
    expect(mergeStep({ attempt: sent, project: project(), git: gitOf() }).branch).toBe('michel/fix-01abc')
    expect(failurePath({ attempt: sent }).steps[3]).toEqual({ key: 'fixed', state: 'now', label: 'fixed_ready' })
  })
  test('manual merge step gives the command', () => {
    expect(mergeStep({ attempt: attempt('applied', { branch: 'michel/fix-01abc' }), project: project() }))
      .toEqual({ mode: 'manual', branch: 'michel/fix-01abc', command: 'git merge michel/fix-01abc', push: null, link: null, update: null, attach: false })
  })
  test('no branch, no command', () => {
    expect(mergeStep({ attempt: attempt('applied'), project: project() }).mode).toBe('none')
    expect(mergeStep({ attempt: null, project: project() }).mode).toBe('none')
    expect(mergeStep({ attempt: attempt('proposed', { branch: 'x' }), project: project() }).mode).toBe('none')
  })
  test('merge step manual, attached, none', () => {
    const a = attempt('applied', { branch: 'michel/fix-01' })
    // Not attached: the command, and the offer only with an address to attach.
    const no = mergeStep({ attempt: a, project: project(), git: gitOf({ attached: false, answer: 'no' }) })
    expect(no.mode).toBe('manual')
    expect(no.command).toBe('git merge michel/fix-01')
    expect(no.attach).toBe(true)
    expect(no.push).toBe(null)
    expect(mergeStep({ attempt: a, project: project(), git: gitOf({ attached: false, answer: '', can_attach: false, reason: 'none' }) }).attach).toBe(false)
    // Attached: no command.
    const yes = mergeStep({ attempt: { ...a, push: openPush() }, project: project(), git: gitOf() })
    expect(yes.mode).toBe('attached')
    expect(yes.command).toBe('')
    expect(yes.push).toEqual({ label: 'git.push.known', params: { provider: 'GitHub' }, pushed: false })
    expect(yes.attach).toBe(false)
    // An address changed: nothing goes, even if the attempt was read before.
    const moved = mergeStep({ attempt: { ...a, push: openPush() }, project: project(), git: gitOf({ attached: false, changed: true }) })
    expect(moved.mode).toBe('manual')
    expect(moved.push).toBe(null)
    expect(moved.attach).toBe(false)
    // A server's fix has nothing to merge.
    expect(mergeStep({ attempt: { ...a, server: { target: { id: 't' } } }, project: null, git: gitOf() }).mode).toBe('none')
  })
  test('an answer just given counts before the attempt is read again', () => {
    const s = mergeStep({ attempt: attempt('applied', { branch: 'michel/fix-01', push: null }), project: project(), git: gitOf() })
    expect(s.mode).toBe('attached')
    expect(s.push.pushed).toBe(false)
  })
  test('pushed shows the link only if safe, else the branch name', () => {
    const a = (merge_url) => attempt('applied', { branch: 'michel/fix-01', push: sentPush({ merge_url }) })
    expect(mergeStep({ attempt: a('https://github.com/demo/app/pull/new/michel/fix-01'), git: gitOf() }).link)
      .toEqual({ href: 'https://github.com/demo/app/pull/new/michel/fix-01', params: { provider: 'GitHub' } })
    for (const bad of ['', 'javascript:alert(1)', 'http://github.com/a', 'https://github.com.example.test/a']) {
      const s = mergeStep({ attempt: a(bad), git: gitOf() })
      expect(s.link, bad).toBe(null)
      expect(s.branch).toBe('michel/fix-01')
      expect(s.push.pushed).toBe(true)
    }
    // Not sent: the link leads nowhere yet.
    expect(mergeStep({ attempt: attempt('applied', { branch: 'b', push: openPush({ merge_url: 'https://github.com/a/b' }) }), git: gitOf() }).link).toBe(null)
  })
  test('unknown service gives the branch name, no link', () => {
    for (const provider of ['other', 'local']) {
      const s = mergeStep({ attempt: attempt('applied', { branch: 'michel/fix-01', push: sentPush({ provider, merge_url: 'https://github.com/a/b' }) }), git: gitOf({ provider, reason: 'other' }) })
      expect(s.push, provider).toEqual({ label: 'git.push.other', params: {}, pushed: true })
      expect(s.link, provider).toBe(null)
      expect(s.branch).toBe('michel/fix-01')
    }
  })
  test('update explains why when not ready', () => {
    const a = attempt('applied', { branch: 'b', push: sentPush() })
    expect(mergeStep({ attempt: a, git: gitOf({ update: { ready: false, current: 'dev', default: 'main', code: 'api.git.dirty', why: 'Ton dossier a des modifications.' } }) }).update)
      .toEqual({ ready: false, why: 'Ton dossier a des modifications.' })
    expect(mergeStep({ attempt: a, git: gitOf({ update: { ready: true, current: 'main', default: 'main', code: '', why: '' } }) }).update).toEqual({ ready: true, why: '' })
    expect(mergeStep({ attempt: a, git: gitOf({ update: null }) }).update).toBe(null)
  })
})

describe('pathSteps', () => {
  test('a terminal plan with nothing started has no step in progress', () => {
    const terminal = projectPlan({ finding: finding(), project: project({ fix_level: 0 }) })
    const shown = pathSteps(failurePath({ attempt: null }), terminal, null).map((s) => s.state)
    expect(shown).toEqual(['done', 'todo', 'todo', 'todo', 'todo'])
  })
  test('a superseded attempt on a terminal plan has no step in progress either', () => {
    const a = attempt('superseded')
    const terminal = projectPlan({ finding: finding(), project: project({ fix_level: 0 }) })
    expect(pathSteps(failurePath({ attempt: a }), terminal, a).map((s) => s.state)).toEqual(['done', 'todo', 'todo', 'todo', 'todo'])
    const running = projectPlan({ finding: finding(), project: project() })
    expect(pathSteps(failurePath({ attempt: a }), running, a).map((s) => s.state)).toEqual(['done', 'now', 'todo', 'todo', 'todo'])
  })
  test('anything else stays as the path says', () => {
    const running = projectPlan({ finding: finding(), project: project() })
    // D-11: nothing started: nothing is « en cours ».
    expect(pathSteps(failurePath({ attempt: null }), running, null).map((s) => s.state)).toEqual(['done', 'todo', 'todo', 'todo', 'todo'])
    const a = attempt('proposed')
    const terminal = projectPlan({ finding: finding(), project: project({ fix_level: 0 }) })
    expect(pathSteps(failurePath({ attempt: a }), terminal, a).map((s) => s.state)).toEqual(['done', 'done', 'now', 'todo', 'todo'])
    expect(pathSteps(failurePath({ attempt: null }), null, null).map((s) => s.state)).toEqual(['done', 'todo', 'todo', 'todo', 'todo'])
  })
})

describe('server plan tells the truth for each case', () => {
  const target = (extra = {}) => ({ id: 't1', name: 'srv-demo', kind: 'vps', classification: 'sensitive', env: 'prod', fix_level: 1, executor: 'user', sudo: 'none', auto_config: false, site_url: 'https://example.test', preprod: null, active: true, ...extra })
  const cfg = (extra = {}) => ({ id: 'sf1', kind: 'server_config', rule: 'PHP-INI-1', package: 'expose_php', fixed_versions: [], location: '/etc/php/php.ini:12', status: 'new', explain: 'PHP says its version.', ...extra })
  const pkg = (extra = {}) => ({ id: 'sf2', kind: 'server_package', ecosystem: 'os', rule: 'USN-1', package: 'openssl', fixed_versions: ['3.0.13'], status: 'new', ...extra })
  const expo = (extra = {}) => ({ id: 'sf3', kind: 'server_exposure', rule: 'EXPO-1', package: 'redis', fixed_versions: [], status: 'new', ...extra })
  const keys = (f, t, a = null) => serverPlan({ finding: f, target: t, attempt: a }).lines.map((l) => l.key.replace('plan.server.', ''))
  const serverTexts = Object.entries(fr).filter(([k]) => k.startsWith('plan.server.'))

  test('a setting on a server without preprod', () => {
    const p = serverPlan({ finding: cfg(), target: target() })
    expect(p.title).toBe('plan.server.title')
    expect(p.action).toBe('prepare')
    expect(p.why).toBe('')
    expect(p.warn).toBe(null)
    expect(p.lines.map((l) => l.key)).toEqual(['plan.server.who', 'plan.server.no_copy', 'plan.server.checks', 'plan.server.no_tests', 'plan.server.approval_user', 'plan.server.choice_user_root', 'plan.server.agent'])
  })
  test('without a site address it says so, for a setting and for an update', () => {
    expect(keys(cfg(), target({ site_url: '' }))).toContain('no_site')
    expect(keys(cfg(), target({ site_url: '' }))).not.toContain('checks')
    expect(keys(pkg(), target({ site_url: '' }))).toContain('package_no_site')
    expect(keys(pkg(), target())).not.toContain('package_no_site')
    expect(fr['plan.server.no_site']).toContain('ne le voit pas')
  })
  test('an update says it cannot be undone, and the snapshot', () => {
    const k = keys(pkg(), target())
    expect(k).toContain('package')
    expect(k).not.toContain('checks')
    expect(fr['plan.server.package']).toContain('Aucun script ne peut l')
    expect(fr['plan.server.package']).toContain('snapshot (')
  })
  test('preparing is not said to run nothing: an update is simulated on the server', () => {
    expect(fr['plan.server.who']).not.toContain("rien n'est lancé")
    expect(fr['plan.server.who']).toContain('ne change rien')
  })
  test('a preprod replaces no_copy and is named; the preprod has its own settings', () => {
    const p = serverPlan({ finding: cfg(), target: target({ preprod: { id: 'p', name: 'srv-pre' } }) })
    expect(p.lines.map((l) => l.key)).not.toContain('plan.server.no_copy')
    expect(p.lines.find((l) => l.key === 'plan.server.preprod').params).toEqual({ name: 'srv-pre' })
    expect(fr['plan.server.approval_user']).toContain('sur ce serveur')
    expect(fr['plan.server.approval_michel']).toContain('sur ce serveur')
  })
  test('who runs it follows executorFor: a root script needs sudo without a password', () => {
    const michel = { executor: 'michel', sudo: 'nopasswd' }
    expect(keys(cfg(), target(michel))).toContain('approval_michel')
    expect(keys(pkg(), target(michel))).toContain('approval_michel')
    expect(keys(cfg(), target({ executor: 'michel', sudo: 'none' }))).toContain('approval_user')
    expect(keys(pkg(), target({ executor: 'michel', sudo: 'none' }))).toContain('approval_user')
    // A .user.ini runs as the connection's own user: no sudo needed.
    expect(keys(cfg({ location: '/srv/www/.user.ini:3' }), target({ executor: 'michel', sudo: 'none' }))).toContain('approval_michel')
  })
  test('level 2 or more tries alone once, on an active server, for a flaw not decided', () => {
    expect(keys(cfg(), target({ fix_level: 1 }))).not.toContain('self_prepare')
    expect(keys(cfg(), target({ fix_level: 2 }))).toContain('self_prepare')
    expect(keys(cfg(), target({ fix_level: 3 }))).toContain('self_prepare')
    expect(keys(cfg(), target({ fix_level: 2, active: false }))).not.toContain('self_prepare')
    expect(keys(cfg({ status: 'decided' }), target({ fix_level: 2 }))).not.toContain('self_prepare')
    expect(keys(cfg(), target({ fix_level: 2 }), attempt('failed'))).not.toContain('self_prepare')
  })
  test('no copy is ever promised', () => {
    const bad = serverTexts.filter(([k, v]) => k !== 'plan.server.no_copy' && v.includes('copie à part'))
    expect(bad).toEqual([])
    expect(fr['plan.server.no_copy']).toContain('copie à part')
  })
  test('the word IA is used only for the agent', () => {
    const withIA = serverTexts.filter(([, v]) => /\bIA\b/.test(v)).map(([k]) => k).sort()
    expect(withIA).toEqual(['plan.server.agent', 'plan.server.hds', 'plan.server.hds_preprod', 'plan.server.who', 'plan.server.who_auto'])
    expect(serverTexts.filter(([, v]) => v.includes("l'IA"))).toEqual([])
  })
  test('the agent is not said to wait for a click: at level 2 it can start alone', () => {
    expect(fr['plan.server.agent']).not.toContain('proposera')
    expect(fr['plan.server.agent']).toContain('ce que Michel reconnaît comme secret')
  })
  test('terminal plans stand alone', () => {
    const r = serverPlan({ finding: cfg(), target: target({ fix_level: 0 }) })
    expect(r.lines.map((l) => l.key)).toEqual(['plan.server.report_only'])
    expect(r.action).toBe(null)
    expect(r.why).toBe('report_only')
    const e = serverPlan({ finding: expo(), target: target() })
    expect(e.lines.map((l) => l.key)).toEqual(['plan.exposure', 'expo.how'])
    expect(e.action).toBe(null)
    expect(e.why).toBe('exposure')
    // Decided: the advice is over, and its button has gone.
    expect(serverPlan({ finding: expo({ status: 'decided' }), target: target() }).lines).toEqual([])
    // Both apply: the exposure first, alone.
    expect(serverPlan({ finding: expo(), target: target({ fix_level: 0 }) }).lines.map((l) => l.key)).toEqual(['plan.exposure', 'expo.how'])
  })
  test('a health server hears only hds', () => {
    for (const t of [target({ kind: 'hds' }), target({ classification: 'health' })]) {
      const k = keys(cfg(), t)
      expect(k).toContain('hds')
      expect(k).not.toContain('agent')
    }
  })
  test('no ready-made fix: no script is promised', () => {
    const none = pkg({ fixed_versions: [] })
    const k = keys(none, target({ fix_level: 2 }))
    expect(k[0]).toBe('no_ready')
    expect(k).not.toContain('who')
    expect(k).not.toContain('package')
    expect(k).not.toContain('self_prepare')
    expect(k).toContain('agent')
    expect(serverPlan({ finding: none, target: target() }).action).toBe('prepare')
    const health = serverPlan({ finding: none, target: target({ kind: 'hds' }) })
    expect(health.action).toBe(null)
    expect(health.lines.map((l) => l.key)).toEqual(['plan.server.no_ready', 'plan.server.hds'])
  })
  test('rule level 3 keeps packages waiting', () => {
    const rule = { fix_level: 3, auto_config: true, executor: 'michel', sudo: 'nopasswd' }
    expect(keys(cfg(), target(rule))).toContain('approval_auto')
    expect(keys(cfg(), target(rule))).not.toContain('approval_michel')
    expect(keys(pkg(), target(rule))).toContain('approval_michel')
    expect(keys(pkg(), target(rule))).not.toContain('approval_auto')
    expect(fr['plan.server.approval_auto']).toContain('attend toujours ton accord')
    expect(fr['plan.server.approval_auto']).toContain('administrateur')
  })
  test('the rule needs every condition AutoApplicableServer needs', () => {
    const rule = { fix_level: 3, auto_config: true, executor: 'michel', sudo: 'nopasswd' }
    expect(keys(cfg(), target({ ...rule, auto_config: false }))).toContain('approval_michel')
    expect(keys(cfg(), target({ ...rule, fix_level: 2 }))).toContain('approval_michel')
    expect(keys(cfg(), target({ ...rule, site_url: '' }))).toContain('approval_michel')
    expect(keys(cfg(), target({ ...rule, executor: 'user' }))).toContain('approval_user')
    expect(keys(cfg(), target({ ...rule, sudo: 'none' }))).toContain('approval_user')
    // A .user.ini has no configuration test: the rule never takes it.
    expect(keys(cfg({ location: '/srv/www/.user.ini:3' }), target(rule))).toContain('approval_michel')
  })
  test('level 3 warning kept', () => {
    for (const n of [0, 1, 2]) expect(serverPlan({ finding: cfg(), target: target({ fix_level: n }) }).warn).toBe(null)
    expect(serverPlan({ finding: cfg(), target: target({ fix_level: 3 }) }).warn).toBe('servers.level.3.warn')
    expect(serverPlan({ finding: pkg(), target: target({ fix_level: 3 }) }).warn).toBe('servers.level.3.warn')
    expect(fr['servers.level.3.warn']).toBeTruthy()
    // An exposure has no fix that could leave alone.
    expect(serverPlan({ finding: expo(), target: target({ fix_level: 3 }) }).warn).toBe(null)
  })
  test('without the server yet nothing is promised', () => {
    const p = serverPlan({ finding: cfg(), target: null })
    expect(p.lines).toEqual([])
    expect(p.action).toBe(null)
    expect(p.warn).toBe(null)
  })
  test('every key exists in both languages', () => {
    for (const k of Object.keys(fr).filter((x) => x.startsWith('plan.server.') || x.startsWith('path.note.') || x === 'plan.exposure' || x === 'expo.how')) expect(en[k], k).toBeTruthy()
    for (const k of ['plan.server.title', 'plan.server.prepare', 'plan.exposure', 'expo.how', 'plain.server_package', 'path.note.no_site']) expect(fr[k], k).toBeTruthy()
  })
})

describe('the path of a flaw on a server', () => {
  const srv = { target: { id: 't', name: 'srv-demo' }, executor: 'michel' }
  const gone = finding({ status: 'gone' })
  const noteOf = (a, extra = {}) => failurePath({ attempt: a, ...extra }).note

  test('server verified needs proven_fixed', () => {
    // site_unchecked (server_exec.go): the recollection says proven, the site was not checked.
    const a = attempt('inconclusive', { server: { ...srv, steps: [{ op: 'recollect', ok: true, detail: 'the check no longer sees the problem' }] }, cause: 'site', finding: gone })
    expect(isVerified(a)).toBe(false)
    const p = failurePath({ attempt: a, vanished: true })
    expect(p.verified).toBe(false)
    expect(states(p)).toEqual(['done', 'done', 'done', 'done', 'stopped'])
    expect(p.note).toEqual({ cause: 'site' })
    expect(isVerified(attempt('proven_fixed', { server: srv, finding: gone }))).toBe(true)
    // A flaw that came back does not stay verified.
    expect(isVerified(attempt('proven_fixed', { server: srv }))).toBe(false)
  })
  test('verified without a site says so', () => {
    const a = attempt('proven_fixed', { server: srv, finding: gone })
    expect(noteOf(a, { target: { site_url: '' } })).toEqual({ key: 'no_site' })
    expect(noteOf(a, { target: { site_url: 'https://example.test' } })).toBe(null)
    // Without the sheet of the server, nothing is said.
    expect(noteOf(a)).toBe(null)
    expect(states(failurePath({ attempt: a, target: { site_url: '' } }))).toEqual(['done', 'done', 'done', 'done', 'done'])
    expect(fr['path.note.no_site']).toContain("n'a pas vérifié")
  })
  test('a server has its own sentences: no project, no branch, no copy', () => {
    expect(noteOf(attempt('approved', { approved_by: 'auto', server: srv })).key).toBe('by_rule_server')
    expect(noteOf(attempt('preparing', { server: srv })).key).toBe('preparing_server')
    expect(noteOf(attempt('proven_fixed', { server: srv })).key).toBe('came_back_server')
    expect(noteOf(attempt('unknown', { server: srv })).key).toBe('unknown_server')
    expect(noteOf(attempt('failed', { server: srv })).key).toBe('failed_server')
    expect(noteOf(attempt('approved', { approved_by: 'kevin', server: { ...srv, executor: 'user' } })).key).toBe('run_yours')
    expect(noteOf(attempt('approved', { approved_by: 'kevin', server: srv }))).toBe(null)
    for (const k of ['by_rule_server', 'preparing_server', 'came_back_server', 'unknown_server', 'failed_server', 'run_yours', 'vanished_server', 'vanished_after_server', 'no_site']) {
      expect(fr[`path.note.${k}`], k).not.toMatch(/projet|branche|ton code/)
    }
    // A failed server fix may have changed something: « rien n'a été appliqué » is never said.
    expect(fr['path.note.failed_server']).not.toContain('rien')
  })
  test('a flaw gone from a server offers no start, and says it of the server', () => {
    expect(noteOf(attempt('failed', { server: srv, finding: gone }), { vanished: true }).key).toBe('vanished_after_server')
    expect(noteOf(null, { vanished: true, target: { site_url: '' } }).key).toBe('vanished_server')
    expect(canPrepareServer(attempt('failed', { server: srv, finding: gone }), true)).toBe(false)
    expect(canPrepareServer(null, true)).toBe(false)
    expect(canPrepareServer(attempt('inconclusive', { server: srv, finding: gone }), true)).toBe(false)
  })
  test('what can be prepared again', () => {
    expect(canPrepareServer(null)).toBe(true)
    for (const s of ['failed', 'refused', 'superseded', 'inconclusive']) expect(canPrepareServer(attempt(s, { server: srv })), s).toBe(true)
    for (const s of ['preparing', 'proposed', 'approved', 'running', 'applied', 'unknown']) expect(canPrepareServer(attempt(s, { server: srv })), s).toBe(false)
    expect(canPrepareServer(attempt('proven_fixed', { server: srv, finding: gone }))).toBe(false)
    // It came back.
    expect(canPrepareServer(attempt('proven_fixed', { server: srv }))).toBe(true)
  })
  test('nothing in progress where nothing can start', () => {
    const plan = { why: 'report_only' }
    expect(pathSteps(failurePath({ attempt: null }), plan, null).map((s) => s.state)).toEqual(['done', 'todo', 'todo', 'todo', 'todo'])
  })
})

describe('plainRisk on a server', () => {
  const upd = { kind: 'server_package', rule: 'USN-1', package: 'openssl', fixed_versions: ['3.0.13'], explain: 'CVE-2024-1 in openssl' }
  test('simple: an update in plain words, else the API', () => {
    expect(plainRisk(upd, null, 'fr', false)).toBe(fr['plain.server_package'])
    expect(plainRisk({ kind: 'server_config', explain: 'PHP dit sa version.' }, null, 'fr', false)).toBe('PHP dit sa version.')
  })
  test('advanced keeps the API sentence', () => {
    expect(plainRisk(upd, null, 'fr', true)).toBe('CVE-2024-1 in openssl')
  })
  test('the update is said to fix it only when it does', () => {
    expect(plainRisk({ ...upd, fixed_versions: [] }, null, 'fr', false)).toBe(fr['plain.server_unfixed'])
    expect(plainRisk({ ...upd, mitigation: true }, null, 'fr', false)).toBe(fr['plain.server_unfixed'])
    expect(plainRisk({ kind: 'server_package', rule: 'PHP-VERSION-UNKNOWN', fixed_versions: [] }, null, 'fr', false)).toBe(fr['servers.finding.php_version_unknown_hint'])
  })
  test('the sheet of the server speaks over the attempt', () => {
    expect(plainRisk({ summary: 'raw' }, { kind: 'server_config', explain: 'Mieux.' }, 'fr', false)).toBe('Mieux.')
  })
})
