// Pure functions behind the Servers page, the server sheet and the server
// fix proposal: no DOM, no fetch, no storage. Vitest covers them
// (serversView.test.js).
import { translate } from '../i18n/index.js'
import { agoText } from './sourcesView.js'

/** The fix levels of a server (target.fix_level), see the spec § 9. */
export const serverLevels = [0, 1, 2, 3]

/** The kinds and environments a server can have. */
export const kinds = ['vps', 'shared', 'hds']
export const envs = ['prod', 'preprod', 'dev']

/** The check intervals the sheet offers ("manual" = only by hand). */
export const intervals = ['manual', '6h', '12h', '24h', '168h']

/** The states of a server's state sentence (TargetState.code). */
const stateCodes = ['inactive', 'checking', 'check_failed', 'key_unconfirmed', 'never_checked', 'findings', 'unread', 'clean']

/** @param {string} kind @param {string} lang @returns {string} the kind in words (HDS, VPS, Mutualisé); an unknown one as it is. */
export function kindLabel(kind, lang) {
  return kinds.includes(kind) ? translate(lang, `servers.kind.${kind}`) : String(kind || '')
}

/** @param {string} env @param {string} lang @returns {string} the environment in words. */
export function envLabel(env, lang) {
  return envs.includes(env) ? translate(lang, `servers.env.${env}`) : String(env || '')
}

/**
 * intervalLabel says how often Michel checks a server: « seulement à la
 * main », « toutes les 24 h », « toutes les 30 min ». "" is the default (24 h).
 * @param {string} interval TargetView.check_interval ("manual", "24h", "30m"…)
 * @param {string} lang
 */
export function intervalLabel(interval, lang) {
  const s = String(interval || '24h').trim()
  if (s === 'manual') return translate(lang, 'servers.interval.manual')
  const m = s.match(/^(\d+)h(?:0m)?(?:0s)?$/)
  if (m) return translate(lang, 'servers.interval.hours', { n: Number(m[1]) })
  const mm = s.match(/^(\d+)m(?:0s)?$/)
  if (mm) return translate(lang, 'servers.interval.minutes', { n: Number(mm[1]) })
  return translate(lang, 'servers.interval.other', { d: s })
}

/**
 * levelLabel names a server's fix level in a sentence: {title, text}; null
 * for a value that is not a level. The text of level 3 says that a fix
 * Michel prepared, even on the user's request, can then run alone when it
 * keeps the rules.
 * @param {number} n
 * @param {string} lang
 */
export function levelLabel(n, lang) {
  if (!serverLevels.includes(n)) return null
  return { title: translate(lang, `servers.level.${n}.title`), text: translate(lang, `servers.level.${n}.text`) }
}

/**
 * serverStateLine is the first sentence of where a server stands: touched by
 * N flaws, nothing known, could not see everything, not checked yet…
 * @param {object|null} target TargetView
 * @param {string} lang
 */
export function serverStateLine(target, lang) {
  if (!target) return ''
  const code = stateCodes.includes(target.state?.code) ? target.state.code : 'clean'
  const t = (key, params) => translate(lang, `servers.state.${key}`, params)
  switch (code) {
    case 'findings':
      return t('findings', { n: Number(target.open_findings) || 0 })
    case 'check_failed':
      // The server's own sentence says why (no SSH agent, key changed…).
      return target.state?.text || t('check_failed')
    default:
      return t(code)
  }
}

/**
 * stateSentence says where a server stands in one sentence, then when
 * Michel last looked: « Touché par 2 failles. Dernière vérification il y a
 * 3 h. »
 * @param {object|null} target TargetView
 * @param {string} lang
 * @param {Date} [now]
 */
export function stateSentence(target, lang, now = new Date()) {
  const head = serverStateLine(target, lang)
  if (!head) return ''
  const code = target.state?.code
  if (!['findings', 'unread', 'clean'].includes(code) || !target.last_check_at) return head
  const ago = agoText(target.last_check_at, now, (key, params) => translate(lang, key, params))
  return ago ? `${head} ${translate(lang, 'servers.state.last', { ago })}` : head
}

/**
 * touchedServers are the servers with open flaws, the most first: the Today
 * page shows them at the top.
 * @param {object[]|null} list GET /targets
 */
export function touchedServers(list) {
  return (Array.isArray(list) ? list : [])
    .filter((t) => t && t.active !== false && Number(t.open_findings) > 0)
    .sort((a, b) => Number(b.open_findings) - Number(a.open_findings))
}

/** The rules whose finding has no text in Michel's catalog, said here. */
const plainRules = { 'PHP-VERSION-UNKNOWN': 'servers.finding.php_version_unknown' }

/**
 * findingTitle is the title of a server finding in words: the catalog's,
 * or for a rule without one (PHP-VERSION-UNKNOWN) a sentence of the page.
 * @param {{rule?: string, osv_id?: string, title?: string, package?: string}} f
 * @param {string} lang
 */
export function findingTitle(f, lang) {
  const rule = f?.rule || f?.osv_id || ''
  if (plainRules[rule]) return translate(lang, plainRules[rule])
  return f?.title || f?.summary || f?.package || rule
}

/** The steps of a server fix, by op, and Michel's own after the script. */
const stepOps = ['backup_file', 'set_directive', 'test_config', 'reload_service', 'package_upgrade', 'check_site', 'undo', 'recollect', 'apply']

/** The details of a step (fix/server_exec.go), by their plain English text. */
const stepDetails = {
  done: 'done',
  'not run': 'not_run',
  'stopped before any change': 'stopped',
  'failed after the change; the script put the files back': 'rolled_back',
  'failed, and putting the files back failed too': 'rollback_bad',
  'the upgrade failed; the package may have changed': 'pkg_failed',
  'PHP complained while reading the file': 'stderr',
  'the site does not answer': 'site_down',
  'no site check is possible from this computer': 'no_site_check',
  'the check still sees the problem': 'still_seen',
  'the check could not judge everything': 'partial',
  'the check did not complete': 'check_failed',
  'the check no longer sees the problem': 'proven',
  'the run ended without an answer (time limit or connection lost)': 'unknown',
  'run by you': 'by_you',
}

/**
 * stepLine says one step of a server fix in one line, with its result:
 * « Copie des fichiers : faite. », « Vérification du site : le site ne
 * répond pas. » Never a raw terminal.
 * @param {{op: string, ok: boolean, detail?: string}|null} step StepView
 * @param {string} lang
 */
export function stepLine(step, lang) {
  if (!step) return ''
  const op = stepOps.includes(step.op) ? step.op : 'other'
  let result = stepDetails[String(step.detail || '').trim()]
  if (!result) result = step.ok ? 'done' : 'failed'
  // A done step reads in the gender of its name in French; undo says more.
  const key = result === 'done' ? `servers.step.done.${op}` : `servers.step.result.${result}`
  return translate(lang, 'servers.step.line', { what: translate(lang, `servers.step.op.${op}`), result: translate(lang, key) })
}

/** isServerAttempt tells whether an AttemptView is a fix of a server. */
export function isServerAttempt(attempt) {
  return !!attempt && !!attempt.server
}

/**
 * needsSnapshot tells whether a server fix waits for the user's snapshot
 * (a package upgrade: no script can undo it). p is the attempt's server
 * part (ServerAttemptView) or the attempt itself.
 * @param {object|null} p
 */
export function needsSnapshot(p) {
  const s = p && p.server ? p.server : p
  return !!(s && s.needs_snapshot)
}

/**
 * canApproveServer tells whether Valider may be offered for a server fix: a
 * proposed attempt with its proposal, and the snapshot done when it needs
 * one (never without it, even at level 3).
 * @param {object|null} attempt AttemptView with server
 * @param {object|null} proposal its current proposal (with its hash)
 */
export function canApproveServer(attempt, proposal) {
  if (!attempt || !attempt.server || attempt.state !== 'proposed' || !proposal || !proposal.hash) return false
  return !needsSnapshot(attempt.server) || !!attempt.server.snapshot_done
}

/** The states of a server fix after which nothing more happens. */
const serverFinals = ['refused', 'proven_fixed', 'inconclusive', 'failed', 'superseded']

/** @param {string} state @returns {boolean} whether a server fix is over (applied is not: Michel checks again). */
export function isServerFinal(state) {
  return serverFinals.includes(state)
}

/**
 * serverAttemptLine says, under a server fix in the Fix page's list, where
 * it stands: waits for the snapshot, for the user's run, approved by the
 * rule and not run yet, running, of unknown outcome…
 * @param {object} attempt AttemptView with server
 * @param {string} lang
 */
export function serverAttemptLine(attempt, lang) {
  const a = attempt || {}
  const s = a.server || {}
  const t = (key) => translate(lang, `servers.line.${key}`)
  switch (a.state) {
    case 'proposed':
      return needsSnapshot(s) && !s.snapshot_done ? t('snapshot') : t('proposed')
    case 'approved':
      if (s.executor === 'user') return t('approved_user')
      return a.approved_by === 'auto' ? t('approved_auto') : t('approved')
    case 'preparing':
    case 'running':
    case 'unknown':
    case 'applied':
    case 'proven_fixed':
    case 'inconclusive':
    case 'refused':
    case 'superseded':
      return t(a.state)
    default:
      return t('failed')
  }
}

/**
 * backupLine says one copy of a server file kept on this computer, and
 * whether it still opens: kept, key lost (sealed with a key that was
 * replaced; never called "does not match"), or damaged.
 * @param {{file: string, state: string}} b BackupView
 * @param {string} lang
 */
export function backupLine(b, lang) {
  const state = ['kept', 'key_lost', 'damaged'].includes(b?.state) ? b.state : 'damaged'
  return translate(lang, `servers.backup.${state}`, { file: b?.file || '' })
}

/**
 * serversRoute reads the Servers page's address: "#/servers" (the list) or
 * "#/servers/<id>" (a server's sheet). null when the hash is not the page.
 * @param {string} hash
 * @returns {{id: string}|null}
 */
export function serversRoute(hash) {
  const m = String(hash || '').match(/^#\/servers(?:\/([^/?#]+))?\/?$/)
  if (!m) return null
  try {
    return { id: decodeURIComponent(m[1] || '') }
  } catch {
    return { id: '' }
  }
}

/** serversHash is the address of a server's sheet ("" for the list). */
export function serversHash(id) {
  return id ? `#/servers/${encodeURIComponent(id)}` : '#/servers'
}
