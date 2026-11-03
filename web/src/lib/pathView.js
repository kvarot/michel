// Pure functions behind the path of a flaw and the true text of what will
// happen on a project. No DOM, no fetch. Each sentence of the plan was checked
// against the code (internal/fix/service.go, auto.go, queue.go,
// internal/workcopy/install.go): when a case is not true for a flaw, the line
// is left out or says less.
import { translate } from '../i18n/index.js'
import { plainSentence } from './modeView.js'

const stepKeys = ['found', 'solution', 'accord', 'fixed', 'verified']

/**
 * isVerified says whether a fix attempt counts as « Vérifiée » (ruling R2).
 * A project's fix needs the proof (state proven_fixed) and a clean new scan of
 * the copy (proposal.rescan_clean): rescan_clean alone is known from the
 * proposal on, before any agreement, so it never lights the step by itself.
 * A server's fix needs the proof only: Michel sets it after a full reading that
 * no longer sees the flaw. inconclusive is never verified. In both cases the
 * flaw must still be gone (finding.status): a proven_fixed attempt never leaves
 * its final state, so a flaw that came back would otherwise stay « Vérifiée ».
 * @param {object|null|undefined} attempt an element of GET /fixes
 * @returns {boolean}
 */
export function isVerified(attempt) {
  if (!attempt || attempt.state !== 'proven_fixed') return false
  if (attempt.finding?.status !== 'gone') return false
  if (attempt.server) return true
  return attempt.proposal?.rescan_clean === true
}

/**
 * cameBack says that a proven fix's flaw is seen again: the attempt stays in
 * its final state, the finding does not.
 * @param {object|null|undefined} attempt
 * @returns {boolean}
 */
export function cameBack(attempt) {
  return attempt?.state === 'proven_fixed' && attempt.finding?.status !== 'gone'
}

/**
 * canRestart says a new fix can start: none yet, the last one ended without a
 * fix, or its flaw came back.
 * @param {object|null|undefined} attempt
 * @returns {boolean}
 */
export function canRestart(attempt) {
  return !attempt || ['failed', 'refused', 'superseded'].includes(attempt.state) || cameBack(attempt)
}

/**
 * showsPlan says the plan is still ahead: it speaks of what will happen, so it
 * goes once the proposal is there (the proposal says what happened).
 * @param {object|null|undefined} attempt
 * @returns {boolean}
 */
export function showsPlan(attempt) {
  return canRestart(attempt) || attempt?.state === 'preparing'
}

/** steps lights the path: all before the index done, the index in that state, the rest to come. */
function steps(index, state) {
  return stepKeys.map((key, i) => ({ key, state: i < index ? 'done' : i === index ? state : 'todo' }))
}

/** causeNote is the API's cause, else the sentence for that state. */
function causeNote(attempt, key) {
  return attempt.cause ? { cause: attempt.cause } : { key }
}

/**
 * failurePath is where a flaw stands on its five steps.
 * note is {key, params} (under path.note.) or {cause} (Michel's own sentence),
 * null when the steps say it all.
 * @param {{attempt?: object|null, gone?: boolean, vanished?: boolean}} args
 *   gone: an exposure without attempt that a full reading no longer sees (R2).
 *   vanished: a project's flaw gone without any fix of Michel's: nothing he did.
 * @returns {{steps: {key: string, state: 'done'|'now'|'todo'|'stopped'}[], verified: boolean, open: boolean, note: object|null}}
 */
export function failurePath({ attempt = null, gone = false, vanished = false } = {}) {
  const out = (index, state, open, note = null, verified = false) => ({ steps: steps(index, state), verified, open, note })
  if (!attempt) {
    if (gone) return { steps: stepKeys.map((key) => ({ key, state: 'done' })), verified: true, open: false, note: null }
    if (vanished) return out(1, 'todo', false, { key: 'vanished' })
    return out(1, 'now', true)
  }
  const server = !!attempt.server
  switch (attempt.state) {
    case 'preparing':
      return out(1, 'now', true, { key: 'preparing' })
    case 'superseded':
      return out(1, 'now', true, { key: 'superseded' })
    case 'proposed':
      return out(2, 'now', true)
    case 'approved':
    case 'running':
      return out(3, 'now', true, attempt.approved_by === 'auto' ? { key: 'by_rule' } : null)
    case 'applied':
      return out(4, 'now', true, server ? { key: 'checking' } : { key: 'merge', params: { branch: attempt.branch || '' } })
    case 'proven_fixed':
      if (isVerified(attempt)) {
        return { steps: stepKeys.map((key) => ({ key, state: 'done' })), verified: true, open: false, note: server ? null : { key: 'deploy' } }
      }
      if (cameBack(attempt)) return out(4, 'stopped', true, { key: 'came_back' })
      return out(4, 'stopped', false, { key: 'copy_not_confirmed' })
    case 'inconclusive':
      return out(4, 'stopped', true, causeNote(attempt, 'inconclusive'))
    case 'refused':
      return out(2, 'stopped', true, { key: 'refused' })
    case 'unknown':
      return out(3, 'stopped', true, { key: 'unknown' })
    case 'failed':
      if (attempt.approved_by) return out(3, 'stopped', true, causeNote(attempt, 'failed'))
      if (attempt.proposal) return out(2, 'stopped', true, causeNote(attempt, 'failed'))
      return out(1, 'stopped', true, causeNote(attempt, 'failed'))
    default:
      return out(1, 'stopped', true, causeNote(attempt, 'failed'))
  }
}

/**
 * pathSteps is what the screen lights. With nothing started on a project where
 * nothing can start (a terminal plan), no step is in progress: Michel prepares
 * nothing, and « en cours » would say he does.
 * @param {{steps: object[]}} path failurePath()
 * @param {{why: string}|null} plan projectPlan()
 * @param {object|null} attempt
 * @returns {{key: string, state: string}[]}
 */
export function pathSteps(path, plan, attempt) {
  if (attempt || !plan?.why) return path.steps
  return path.steps.map((s) => (s.state === 'now' ? { ...s, state: 'todo' } : s))
}

/** baseName is the file name of a manifest path. */
function baseName(rel) {
  return String(rel || '').replaceAll('\\', '/').split('/').pop()
}

/**
 * updateLine is what Michel updates, as buildPlan (internal/fix/service.go)
 * builds it: a known version, composer.lock with Packagist or package-lock.json
 * with npm. An indirect dependency is updated without a pinned version, and
 * without the analysis several fixed versions leave the target open: the
 * version is then not named.
 */
function updateLine(f) {
  const target = f.analysis?.upgrade?.target || ''
  const fixed = f.fixed_versions || []
  const base = baseName(f.manifest_rel_path)
  const runs = (f.ecosystem === 'Packagist' && base === 'composer.lock') || (f.ecosystem === 'npm' && base === 'package-lock.json')
  if (!runs || (!target && !fixed.length)) return { key: 'plan.project.search' }
  const to = target || (fixed.length === 1 ? fixed[0] : '')
  if (!to || f.analysis?.path?.directness === 'transitive') return { key: 'plan.project.update_any', params: { package: f.package } }
  return { key: 'plan.project.update', params: { package: f.package, to } }
}

/** testLines says what runs after the agent, as Propose does (internal/fix/service.go). */
function testLines(f, project) {
  const base = baseName(f.manifest_rel_path)
  const yarnOrPnpm = base === 'yarn.lock' || base === 'pnpm-lock.yaml'
  const installs = base === 'composer.lock' || base === 'package-lock.json'
  const out = []
  if (!yarnOrPnpm && !installs) return [{ key: 'plan.project.no_install_kind' }]
  if (!project.has_test_cmd) out.push({ key: 'plan.project.no_tests' })
  else if (!yarnOrPnpm) out.push({ key: 'plan.project.tests' })
  if (yarnOrPnpm) out.push({ key: 'plan.project.no_install' })
  return out
}

/** selfStarts follows fix.Eligible (internal/fix/queue.go) and the worker's refusal check. */
function selfStarts(f, attempt) {
  if ((f.kind && f.kind !== 'dependency') || !(f.fixed_versions || []).length) return false
  if (['defer', 'ignore'].includes(f.decision?.action)) return false
  return attempt?.state !== 'refused'
}

/**
 * projectPlan is the true text of what will happen on a project. A plan with
 * action null is terminal: it holds that one line, since « always » is only
 * true of a plan that runs. Without the project yet, nothing is promised.
 * @param {{finding: object, project: object|null, level?: number, attempt?: object|null}} args
 *   finding is GET /findings/{id} when known (it has the analysis), else the list's.
 * @returns {{title: string, lines: {key: string, params?: object}[], action: 'start'|null, why: string}}
 */
export function projectPlan({ finding, project, level, attempt = null }) {
  if (!project) return { title: 'plan.project.title', lines: [], action: null, why: '' }
  const lvl = level ?? project.fix_level
  const terminal = !project.git_repo ? 'no_git' : project.classification === 'health' ? 'health' : lvl === 0 ? 'report_only' : ''
  if (terminal) return { title: 'plan.project.title_michel', lines: [{ key: `plan.project.${terminal}` }], action: null, why: terminal }
  const f = finding || {}
  const lines = [{ key: 'plan.project.copy' }, updateLine(f), ...testLines(f, project)]
  lines.push({ key: lvl === 3 && project.auto_fix_minor ? 'plan.project.approval_auto' : 'plan.project.approval' })
  if (lvl >= 2 && selfStarts(f, attempt)) lines.push({ key: 'plan.project.self_start' })
  lines.push({ key: 'plan.project.data' })
  return { title: 'plan.project.title', lines, action: 'start', why: '' }
}

/**
 * plainRisk is « Ce que ça veut dire »: the flaw's impact sentence, without
 * technical ids or file names in the simple mode.
 * @param {object} finding the list's finding
 * @param {object|null} sheet GET /findings/{id}
 * @param {string} lang
 * @param {boolean} advanced
 * @returns {string}
 */
export function plainRisk(finding, sheet, lang, advanced) {
  const text = sheet?.explanation?.impact || sheet?.summary || finding?.summary
  if (!text) return translate(lang, 'path.means_none')
  return advanced ? text : plainSentence(text, sheet || finding)
}

/**
 * mergeStep is the last step left to the person once the branch exists.
 * Michel never merges (R6). A server's fix has nothing to merge. Task 14g adds
 * the attached project (R19).
 * @param {{attempt: object|null, project: object|null}} args
 * @returns {{mode: 'manual'|'none', branch: string, command: string}}
 */
export function mergeStep({ attempt }) {
  if (!attempt || attempt.server || attempt.state !== 'applied' || !attempt.branch) return { mode: 'none', branch: '', command: '' }
  return { mode: 'manual', branch: attempt.branch, command: `git merge ${attempt.branch}` }
}
