// Pure functions behind the path of a flaw and the true text of what will
// happen on a project. No DOM, no fetch. Each sentence of the plan was checked
// against the code (internal/fix/service.go, auto.go, queue.go,
// internal/workcopy/install.go): when a case is not true for a flaw, the line
// is left out or says less.
import { translate } from '../i18n/index.js'
import { plainSentence } from './modeView.js'

const stepKeys = ['found', 'solution', 'accord', 'fixed', 'verified']

/**
 * noCopyCheck says no rescan of the copy can run on this flaw: a flaw found by
 * an external tool (Semgrep, Trivy…) has no ecosystem, and rescan
 * (internal/fix/service.go) then fails, so rescan_clean is false whatever the
 * agent did. It says nothing about the flaw. A finding with no status is not
 * one of these: the store no longer has it, so nothing is known of it.
 * @param {object|null|undefined} attempt
 * @returns {boolean}
 */
function noCopyCheck(attempt) {
  return !!attempt && !attempt.server && !!attempt.finding?.status && attempt.finding.ecosystem === ''
}

/**
 * isVerified says whether a fix attempt counts as « Vérifiée » (ruling R2, and
 * the owner's decision on code flaws). It needs the proof (state proven_fixed)
 * and a flaw still gone (finding.status): a proven_fixed attempt never leaves
 * its final state, so a flaw that came back would otherwise stay « Vérifiée ».
 * A project's fix also needs a clean new scan of the copy
 * (proposal.rescan_clean) where such a scan could run: rescan_clean alone is
 * known from the proposal on, before any agreement, so it never lights the step
 * by itself. A server's fix needs nothing more: Michel sets the proof after a
 * full reading that no longer sees the flaw. inconclusive is never verified.
 * @param {object|null|undefined} attempt an element of GET /fixes
 * @returns {boolean}
 */
export function isVerified(attempt) {
  if (!attempt || attempt.state !== 'proven_fixed') return false
  if (attempt.finding?.status !== 'gone') return false
  if (attempt.server || noCopyCheck(attempt)) return true
  return attempt.proposal?.rescan_clean === true
}

/**
 * rescanKey is the sentence for the new scan of the copy. A flaw no scan can
 * look at is never said to be still there.
 * @param {object|null|undefined} attempt
 * @returns {string}
 */
export function rescanKey(attempt) {
  if (attempt?.proposal?.rescan_clean) return 'fix.proposal.rescan_clean'
  return noCopyCheck(attempt) ? 'fix.proposal.rescan_unknown' : 'fix.proposal.rescan_dirty'
}

/**
 * isGone says the flaw is no longer seen. The sheet is the fresher reading.
 * @param {object|null|undefined} finding
 * @param {object|null|undefined} sheet
 * @returns {boolean}
 */
export function isGone(finding, sheet) {
  return (sheet?.status || finding?.status) === 'gone'
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
 * fix, or its flaw came back. Never on a flaw already gone: it would send the
 * code to Anthropic for nothing, and Start does not read the status.
 * @param {object|null|undefined} attempt
 * @param {boolean} [gone] isGone()
 * @returns {boolean}
 */
export function canRestart(attempt, gone = false) {
  if (gone) return false
  return !attempt || ['failed', 'refused', 'superseded', 'withdrawn'].includes(attempt.state) || cameBack(attempt)
}

/**
 * holdView is the question of a held attempt: possible keys found in the copy,
 * no agent started (internal/fix/hold.go). Files and lines only: the API never
 * has a value. A flaw that left keeps its question but not its yes: ContinueHeld
 * would refuse it.
 * @param {object|null|undefined} attempt
 * @param {boolean} [gone] isGone()
 * @returns {{count: number, files: {file: string, linesKey: string, lines: string}[], more: number, hash: string, canContinue: boolean}|null}
 */
export function holdView(attempt, gone = false) {
  if (attempt?.state !== 'held' || !attempt.hold) return null
  const { count, files, more, hash } = attempt.hold
  return {
    count,
    more,
    hash,
    canContinue: !gone,
    files: (files || []).map((f) => ({ file: f.file, linesKey: f.lines.length > 1 ? 'path.hold.lines' : 'path.hold.line', lines: f.lines.join(', ') })),
  }
}

/**
 * canPrepareServer says a new fix of a server's flaw can be prepared: as
 * canRestart, and after an inconclusive fix too, since a server has no merge to
 * wait for and StartServer takes it (only a flaw gone or a server busy refuses).
 * @param {object|null|undefined} attempt
 * @param {boolean} [gone] isGone()
 * @returns {boolean}
 */
export function canPrepareServer(attempt, gone = false) {
  return canRestart(attempt, gone) || (!gone && attempt?.state === 'inconclusive')
}

/**
 * showsPlan says the plan is still ahead: it speaks of what will happen, so it
 * goes once the proposal is there (the proposal says what happened). On a
 * server only an agent's attempt stays in preparing, and the plan speaks of a
 * script Michel writes himself.
 * @param {object|null|undefined} attempt
 * @param {boolean} [gone] isGone()
 * @returns {boolean}
 */
export function showsPlan(attempt, gone = false) {
  if (attempt?.server) return canPrepareServer(attempt, gone)
  return canRestart(attempt, gone) || attempt?.state === 'preparing'
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
 * exposurePath is the path of a service open to all, which has no fix: Michel
 * cannot close it, and from inside the server he only sees whether it is still
 * open. So it has neither « Corrigée » nor « Vérifiée »: the service may have
 * moved or stopped, and the last step says only what he sees (R47). Gone leaves
 * the person's step unlit: nothing says who did what.
 * @param {{gone?: boolean, decided?: boolean}} [args]
 * @returns {{steps: {key: string, state: 'done'|'now'|'todo'}[], verified: false, open: boolean, note: null}}
 */
export function exposurePath({ gone = false, decided = false } = {}) {
  const middle = gone ? 'todo' : decided ? 'done' : 'now'
  return {
    steps: [
      { key: 'found', state: 'done' },
      { key: decided ? 'expo_decided' : 'expo_yours', state: middle },
      { key: 'expo_gone', state: gone ? 'done' : 'todo' },
    ],
    verified: false,
    open: !gone,
    note: null,
  }
}

/**
 * failurePath is where a flaw stands on its five steps.
 * note is {key, params} (under path.note.) or {cause} (Michel's own sentence),
 * null when the steps say it all.
 * @param {{attempt?: object|null, gone?: boolean, vanished?: boolean, target?: object|null}} args
 *   gone: an exposure without attempt that a full reading no longer sees (R47).
 *   vanished: a flaw gone without any fix of Michel's: nothing he did.
 *   target: the server's TargetView (the attempt's has neither site_url nor
 *   settings): a proof with no site address says the site was not looked at.
 *   A step may carry label, the word to show instead of its own (path.step.).
 * @returns {{steps: {key: string, state: 'done'|'now'|'todo'|'stopped', label?: string}[], verified: boolean, open: boolean, note: object|null}}
 */
export function failurePath({ attempt = null, gone = false, vanished = false, target = null } = {}) {
  const path = attemptPath(attempt, gone, vanished, target)
  if (!attempt || !vanished || !canRestart(attempt)) return path
  // The attempt went nowhere and the flaw left on its own: its path stays, with
  // nothing in progress, and nothing is left to start. A failed server fix may
  // have changed something: Michel only says he does not know.
  return {
    ...path,
    steps: path.steps.map((s) => (s.state === 'now' ? { ...s, state: 'todo' } : s)),
    open: false,
    note: { key: attempt.server ? 'vanished_after_server' : 'vanished_after' },
  }
}

/** attemptPath is the table of the path, one line per state. */
function attemptPath(attempt, gone, vanished, target) {
  const out = (index, state, open, note = null, verified = false) => ({ steps: steps(index, state), verified, open, note })
  if (!attempt) {
    if (gone) return exposurePath({ gone: true })
    if (vanished) return out(1, 'todo', false, { key: target ? 'vanished_server' : 'vanished' })
    return out(1, 'now', true)
  }
  const server = !!attempt.server
  switch (attempt.state) {
    case 'preparing':
      return out(1, 'now', true, { key: server ? 'preparing_server' : 'preparing' })
    case 'held': {
      const p = out(1, 'now', true, { key: 'held', params: { n: attempt.hold?.count ?? 0 } })
      p.steps[1] = { ...p.steps[1], label: 'held' }
      return p
    }
    case 'withdrawn':
      return out(1, 'todo', true, { key: 'withdrawn' })
    case 'superseded':
      return out(1, 'now', true, { key: 'superseded' })
    case 'proposed':
      return out(2, 'now', true, noCopyCheck(attempt) ? { key: 'not_checked' } : null)
    case 'approved':
    case 'running':
      if (attempt.approved_by === 'auto') return out(3, 'now', true, { key: server ? 'by_rule_server' : 'by_rule' })
      return out(3, 'now', true, attempt.state === 'approved' && attempt.server?.executor === 'user' ? { key: 'run_yours' } : null)
    case 'applied': {
      if (server) return out(4, 'now', true, { key: 'checking' })
      // On a project the fix waits on its branch: Corrigée is only done once it
      // is proven in the code, and what is left is the person's to do.
      const p = out(3, 'now', true, { key: 'merge', params: { branch: attempt.branch || '' } })
      p.steps[3] = { ...p.steps[3], label: 'fixed_ready' }
      return p
    }
    case 'proven_fixed':
      if (isVerified(attempt)) {
        // prove (server_exec.go) has no site to check without an address.
        const serverNote = target && !target.site_url ? { key: 'no_site' } : null
        const note = server ? serverNote : { key: noCopyCheck(attempt) ? 'deploy_unchecked' : 'deploy' }
        return { steps: stepKeys.map((key) => ({ key, state: 'done' })), verified: true, open: false, note }
      }
      if (cameBack(attempt)) return out(4, 'stopped', true, { key: server ? 'came_back_server' : 'came_back' })
      return out(4, 'stopped', false, { key: 'copy_not_confirmed' })
    case 'inconclusive':
      // Not proven in the code either: gone but not merged, or merged but seen.
      return out(server ? 4 : 3, 'stopped', true, causeNote(attempt, 'inconclusive'))
    case 'refused':
      // A script the person runs may have run: on a server only Michel's part is known.
      return out(2, 'stopped', true, { key: server ? 'refused_server' : 'refused' })
    case 'unknown':
      return out(3, 'stopped', true, { key: server ? 'unknown_server' : 'unknown' })
    case 'failed': {
      // « rien n'a été appliqué » is not known of a server: a script can fail after its change.
      const failed = server ? 'failed_server' : 'failed'
      if (attempt.approved_by) return out(3, 'stopped', true, causeNote(attempt, failed))
      if (attempt.proposal) return out(2, 'stopped', true, causeNote(attempt, failed))
      return out(1, 'stopped', true, causeNote(attempt, failed))
    }
    default:
      return out(1, 'stopped', true, causeNote(attempt, server ? 'failed_server' : 'failed'))
  }
}

/**
 * pathSteps is what the screen lights. With nothing started (or an attempt
 * replaced) on a project where nothing can start (a terminal plan), no step is
 * in progress: Michel prepares nothing, and « en cours » would say he does.
 * @param {{steps: object[]}} path failurePath()
 * @param {{why: string}|null} plan projectPlan()
 * @param {object|null} attempt
 * @returns {{key: string, state: string}[]}
 */
export function pathSteps(path, plan, attempt) {
  if ((attempt && attempt.state !== 'superseded') || !plan?.why) return path.steps
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
  const composer = f.ecosystem === 'Packagist' && base === 'composer.lock'
  const runs = composer || (f.ecosystem === 'npm' && base === 'package-lock.json')
  if (!target && !fixed.length) return { key: 'plan.project.search' }
  // A version is known, but Michel has no command for this file (yarn, pnpm).
  if (!runs) return { key: 'plan.project.update_agent' }
  const to = target || (fixed.length === 1 ? fixed[0] : '')
  if (!to || f.analysis?.path?.directness === 'transitive') return { key: 'plan.project.update_any', params: { package: f.package } }
  // composer takes pkg:^to, which usually resolves higher; npm pins it exactly.
  return { key: composer ? 'plan.project.update_near' : 'plan.project.update', params: { package: f.package, to } }
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
  const tests = testLines(f, project)
  const lines = [{ key: 'plan.project.copy' }, updateLine(f), ...tests]
  // The rule needs tests that passed: without tests it can never apply.
  const auto = lvl === 3 && project.auto_fix_minor && tests.some((l) => l.key === 'plan.project.tests')
  lines.push({ key: auto ? 'plan.project.approval_auto' : 'plan.project.approval' })
  if (lvl >= 2 && selfStarts(f, attempt)) lines.push({ key: 'plan.project.self_start' })
  lines.push({ key: 'plan.project.data' })
  return { title: 'plan.project.title', lines, action: 'start', why: '' }
}

/**
 * rootScript says the fix of a server's flaw runs as root: a package, or any
 * file but a .user.ini (Bundle.RunAsRoot, internal/serverfix).
 */
function rootScript(f) {
  return f.kind === 'server_package' || baseName(String(f.location || '').replace(/:\d+$/, '')) !== '.user.ini'
}

/**
 * serverPlan is the true text of what will happen on a server. Each line was
 * checked against internal/fix (server.go, server_auto.go, server_exec.go) and
 * internal/serverfix/validate.go. A plan with action null is terminal: it holds
 * only its own lines, since « always » is only true of a script that will exist.
 * @param {{finding: object, target: object|null, attempt?: object|null, tried?: boolean, preprodHealth?: boolean, preprodTarget?: object|null}} args
 *   finding is the TargetFindingView, target the TargetView. tried: an attempt on
 *   its preprod was made for this flaw, which serverTried counts. preprodHealth:
 *   the preprod holds health data, so startServerAgent refuses here too.
 *   preprodTarget is the preprod's TargetView: the first script runs there under
 *   its own settings. A preprod whose settings are unknown makes no promise of a
 *   click nor of a run alone.
 * @returns {{title: string, lines: {key: string, params?: object}[], action: 'prepare'|null, why: string, warn: string|null}}
 */
export function serverPlan({ finding, target, attempt = null, tried = false, preprodHealth = false, preprodTarget = null }) {
  const title = 'plan.server.title'
  const none = (lines, why) => ({ title, lines: lines.map((l) => (typeof l === 'string' ? { key: l } : l)), action: null, why, warn: null })
  if (!target) return none([], '')
  const f = finding || {}
  if (f.kind === 'server_exposure') return none(['plan.exposure', 'expo.how'], 'exposure')
  if (target.fix_level === 0) return none(['plan.server.report_only'], 'report_only')
  const health = target.kind === 'hds' || target.classification === 'health'
  const noAgent = health ? { key: 'plan.server.hds' } : { key: 'plan.server.hds_preprod', params: { name: target.preprod?.name || '' } }
  const pkg = f.kind === 'server_package'
  // planFor (server.go) plans a package only of the system (ecosystem os), with a
  // fixed version. PHP's own flaws (php-upstream) have no plan.
  const ready = !pkg || (f.ecosystem === 'os' && !!(f.fixed_versions || [])[0])
  if (!ready && (health || preprodHealth)) return none(['plan.server.no_ready', noAgent], 'no_ready')

  const site = !!target.site_url
  // executorFor (server.go): a root script is Michel's only with sudo without a password.
  const root = rootScript(f)
  // With a preprod the first script runs there, under the preprod's settings.
  const set = target.preprod ? preprodTarget : target
  const michel = !!set && set.executor === 'michel' && (!root || set.sudo === 'nopasswd')
  // AutoApplicableServer (server_auto.go): only a tested configuration, so a root
  // file. ApplyAutoServer takes it right after it is prepared, even after a click.
  const auto = michel && !pkg && root && set.fix_level === 3 && !!set.auto_config && !!set.site_url

  const lines = [{ key: !ready ? 'plan.server.no_ready' : auto ? 'plan.server.who_auto' : 'plan.server.who' }]
  if (target.preprod) lines.push({ key: 'plan.server.preprod', params: { name: target.preprod.name } })
  else lines.push({ key: auto ? 'plan.server.no_copy_auto' : 'plan.server.no_copy' })
  if (!pkg) lines.push({ key: site ? 'plan.server.checks' : 'plan.server.no_site' })
  else if (ready) {
    lines.push({ key: 'plan.server.package' })
    if (!site) lines.push({ key: 'plan.server.package_no_site' })
  }
  lines.push({ key: 'plan.server.no_tests' })

  if (set) lines.push({ key: `plan.server.approval_${auto ? 'auto' : michel ? 'michel' : 'user'}` })
  if (michel && !auto && root) lines.push({ key: 'plan.server.root' })

  // EligibleServer and serverTried (server_auto.go): once, on an active server;
  // a decision may be to defer or ignore, and this view does not say which.
  if (target.fix_level >= 2 && ready && target.active !== false && !attempt && !tried && f.status !== 'decided') lines.push({ key: 'plan.server.self_prepare' })
  lines.push(health || preprodHealth ? noAgent : { key: 'plan.server.agent' })
  return { title, lines, action: 'prepare', why: '', warn: target.fix_level === 3 ? 'servers.level.3.warn' : null }
}

/**
 * chatNoStart says the advanced conversation offers no start, as the guide
 * holds the button. At level 0 the guide has none, and the advanced mode keeps
 * this way in (R14). A project no fix can run on, or a flaw already gone, offers
 * none anywhere.
 * @param {{guided: boolean, project: object|null, gone?: boolean}} args
 * @returns {boolean}
 */
export function chatNoStart({ guided, project, gone = false }) {
  if (!guided) return false
  if (gone) return true
  return !project || projectPlan({ finding: null, project }).why !== 'report_only'
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
  const flaw = sheet || finding
  if (String(flaw?.kind || '').startsWith('server_')) return serverRisk(flaw, lang, advanced)
  const text = sheet?.explanation?.impact || sheet?.summary || finding?.summary
  if (!text) return translate(lang, 'path.means_none')
  return advanced ? text : plainSentence(text, sheet || finding)
}

/**
 * serverRisk is « Ce que ça veut dire » for a server's flaw (TargetFindingView).
 * The update is said to fix it only when a fixed version exists and it is more
 * than a mitigation.
 */
function serverRisk(f, lang, advanced) {
  if (f.rule === 'PHP-VERSION-UNKNOWN') return translate(lang, 'servers.finding.php_version_unknown_hint')
  if (f.kind === 'server_package' && !advanced) {
    return translate(lang, (f.fixed_versions || []).length && !f.mitigation ? 'plain.server_package' : 'plain.server_unfixed')
  }
  return f.explain || f.title || f.summary || translate(lang, 'path.means_none')
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
