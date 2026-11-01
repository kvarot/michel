// Pure functions behind the Fix page: no DOM, no fetch, no storage.
// Vitest covers them (fixView.test.js).
import { translate } from '../i18n/index.js'

/** The four groups of the page's list, in the order they show. */
export const fixGroups = ['todo', 'running', 'review', 'done']

/** The fix levels of a project (project.fix_level), see the spec § 4. */
export const levels = [0, 1, 2, 3]

/** The states after which nothing more happens to an attempt. */
const finals = ['refused', 'applied', 'proven_fixed', 'inconclusive', 'failed', 'superseded']

/** @param {string} state @returns {boolean} whether the attempt is over (the stream can stop). */
export function isFinal(state) {
  return finals.includes(state)
}

/**
 * groupOf is the group of an attempt state: still to fix after a refusal or
 * a failure, running while the agent works or Michel applies an approved
 * fix (or runs a server fix's script), to review once proposed or when a
 * server fix's outcome is unknown (the user checks the server), done once
 * the branch exists or the script ran.
 * @param {string} state
 */
export function groupOf(state) {
  switch (state) {
    case 'preparing':
    case 'approved':
    case 'running':
      return 'running'
    case 'proposed':
    case 'unknown':
      return 'review'
    case 'applied':
    case 'proven_fixed':
    case 'inconclusive':
      return 'done'
    default:
      return 'todo'
  }
}

/**
 * groupAttempts makes the page's list: one line per finding, in the four
 * groups of fixGroups (always all four, maybe empty). list is GET /fixes
 * (newest first): a finding's newest attempt stands for it. findings are the
 * open findings ({id, package, project, ...}); those without an attempt in
 * progress, to review or done go to "todo" after the attempts there. A
 * failed or refused attempt whose finding is gone is left out.
 * Each line is {kind: 'attempt', attempt, findingId} or {kind: 'finding',
 * finding, findingId}.
 * @param {object[]|null} list
 * @param {object[]} [findings]
 * @returns {{key: string, items: object[]}[]}
 */
export function groupAttempts(list, findings = []) {
  const groups = Object.fromEntries(fixGroups.map((k) => [k, []]))
  const seen = new Set()
  for (const a of Array.isArray(list) ? list : []) {
    const fid = a?.finding?.id || ''
    if (!a || seen.has(fid)) continue
    seen.add(fid)
    const g = groupOf(a.state)
    if (g === 'todo' && a.finding?.status === 'gone') continue
    groups[g].push({ kind: 'attempt', attempt: a, findingId: fid })
  }
  for (const f of Array.isArray(findings) ? findings : []) {
    if (!f || seen.has(f.id)) continue
    seen.add(f.id)
    groups.todo.push({ kind: 'finding', finding: f, findingId: f.id })
  }
  return fixGroups.map((key) => ({ key, items: groups[key] }))
}

/**
 * proposalFacts gathers what proposalSentence says: the package, the
 * versions the proposal moves it between (from_version / to_version, what
 * the fix commit's lockfile resolves); for an older proposal without them,
 * the installed version and the analysis' target (else the first fixed
 * version). Then the number of call sites (null when there is no
 * analysis) and the tests of the proposal.
 * @param {object} attempt AttemptView
 * @param {object|null} sheet the finding as GET /findings/{id} answers it
 */
export function proposalFacts(attempt, sheet) {
  const f = attempt?.finding || {}
  const a = sheet?.analysis || null
  const p = attempt?.proposal || {}
  return {
    package: f.package || '',
    from: p.from_version || f.installed_version || '',
    to: p.to_version || a?.upgrade?.target || (f.fixed_versions || [])[0] || '',
    sites: a && a.calls ? Number(a.calls.count) || 0 : null,
    tests: attempt?.proposal?.tests_status || 'not_run',
  }
}

/**
 * proposalSentence says the proposal in Michel's voice, e.g. « Je passe
 * guzzlehttp/guzzle de 7.4.0 à 7.4.5 ; 12 endroits l'utilisent, les tests
 * passent. » Without a target it says the package is updated; without
 * analysis (sites null) the call sites are left out.
 * @param {{package: string, from: string, to: string, sites: number|null, tests: string}|null} facts
 * @param {string} lang
 */
export function proposalSentence(facts, lang) {
  if (!facts) return ''
  const t = (key, params) => translate(lang, key, params)
  const head = facts.to
    ? t('fix.proposal.move', { package: facts.package, from: facts.from || '?', to: facts.to })
    : t('fix.proposal.update', { package: facts.package, from: facts.from || '?' })
  const parts = []
  if (typeof facts.sites === 'number') {
    parts.push(facts.sites > 0 ? t('fix.proposal.sites', { n: facts.sites }) : t('fix.proposal.no_sites'))
  }
  const tests = ['passed', 'failed', 'not_run'].includes(facts.tests) ? facts.tests : 'not_run'
  parts.push(t(`fix.proposal.tests_${tests}`))
  return t('fix.proposal.sentence', { head, rest: parts.join(', ') })
}

/** @param {object|null} attempt @returns {boolean} whether Valider may be offered: a proposed attempt with its proposal. */
export function canApprove(attempt) {
  return !!attempt && attempt.state === 'proposed' && !!attempt.proposal && !!attempt.proposal.hash
}

/**
 * levelLabel names a fix level in a sentence: {title, text}; null for a
 * value that is not a level.
 * @param {number} n
 * @param {string} lang
 */
export function levelLabel(n, lang) {
  if (!levels.includes(n)) return null
  return { title: translate(lang, `fix.level.${n}.title`), text: translate(lang, `fix.level.${n}.text`) }
}

/**
 * activityLine says in one line what the agent does, from an "activity"
 * event (a MessageView of role tool, text "<Tool> <summary>"): it reads a
 * file, changes a file, searches the code, sends its proposal. The agent
 * has no command tool (ruling 33): Michel runs the update, the install and
 * the tests himself and says so in the conversation.
 * @param {{text: string}|null} event
 * @param {string} lang
 */
export function activityLine(event, lang) {
  if (!event || typeof event.text !== 'string') return ''
  const text = event.text.trim()
  const space = text.indexOf(' ')
  const tool = space < 0 ? text : text.slice(0, space)
  const rest = space < 0 ? '' : text.slice(space + 1).trim()
  const t = (key, params) => translate(lang, `fix.activity.${key}`, params)
  if (/propose_fix/.test(tool)) return t('propose')
  if (tool.startsWith('mcp__')) return t('ask_michel')
  switch (tool) {
    case 'Read':
      return rest ? t('read', { file: rest }) : t('read_any')
    case 'Edit':
    case 'MultiEdit':
    case 'Write':
    case 'NotebookEdit':
      return rest ? t('edit', { file: rest }) : t('edit_any')
    case 'Grep':
    case 'Glob':
    case 'LS':
      return t('search')
    case 'TodoWrite':
      return t('plan')
    default:
      return t('working')
  }
}

/**
 * mergeMessages adds msg to list once (by id), keeping the order of the
 * times, then of arrival: a reconnect replays the whole conversation. The
 * list is copied; a missing msg returns list itself.
 * @param {object[]} list
 * @param {{id: string, at?: string}|null} msg
 */
export function mergeMessages(list, msg) {
  if (!msg || !msg.id) return list
  if (list.some((m) => m.id === msg.id)) return list
  const out = [...list, msg]
  const at = (m) => {
    const t = new Date(m.at || '').getTime()
    return Number.isNaN(t) ? Infinity : t
  }
  return out.map((m, i) => ({ m, i })).sort((a, b) => at(a.m) - at(b.m) || a.i - b.i).map((x) => x.m)
}

// A masked secret, whole, in Michel's exact token shape (the same as
// mask.HasToken): Michel never shows a fragment (ruling 38), and a text
// such as "[secret-key]" in a library stays plain text.
const maskToken = /\[secret-[0-9a-f]{8}-[0-9]+\]/g

/**
 * splitMasked cuts a text into plain parts ({text}) and masked secrets
 * ({secret}), so the page shows each token as a "secret masqué" chip.
 * @param {string} text
 * @returns {({text: string}|{secret: string})[]}
 */
export function splitMasked(text) {
  const s = String(text || '')
  const out = []
  let last = 0
  for (const m of s.matchAll(maskToken)) {
    if (m.index > last) out.push({ text: s.slice(last, m.index) })
    out.push({ secret: m[0] })
    last = m.index + m[0].length
  }
  if (last < s.length) out.push({ text: s.slice(last) })
  return out
}

/**
 * stateLine says, under a line of the list, where it stands.
 * @param {{kind: string, attempt?: object}} item a line of groupAttempts
 * @param {string} lang
 */
export function stateLine(item, lang) {
  if (!item || item.kind !== 'attempt') return translate(lang, 'fix.line.none')
  const a = item.attempt || {}
  const known = ['preparing', 'proposed', 'approved', 'refused', 'applied', 'proven_fixed', 'inconclusive', 'failed', 'superseded']
  return translate(lang, `fix.line.${known.includes(a.state) ? a.state : 'failed'}`, { branch: a.branch || '' })
}

/**
 * fixRoute reads the Fix page's address: "#/fix" (nothing chosen),
 * "#/fix/<attempt>" (an attempt) or "#/fix?finding=<id>" (a finding not
 * started yet). null when the hash is not the Fix page.
 * @param {string} hash
 * @returns {{attempt: string, finding: string}|null}
 */
export function fixRoute(hash) {
  const m = String(hash || '').match(/^#\/fix(?:\/([^/?#]+))?\/?(?:\?finding=([^&#]+))?$/)
  if (!m) return null
  const dec = (s) => {
    try {
      return decodeURIComponent(s || '')
    } catch {
      return ''
    }
  }
  return { attempt: dec(m[1]), finding: m[1] ? '' : dec(m[2]) }
}

/** fixHash is the address of an attempt ({attempt}) or of a finding to fix ({finding}). */
export function fixHash({ attempt = '', finding = '' } = {}) {
  if (attempt) return `#/fix/${encodeURIComponent(attempt)}`
  if (finding) return `#/fix?finding=${encodeURIComponent(finding)}`
  return '#/fix'
}

/**
 * selectAction decides what the Fix page does for its address. shownId is
 * the attempt on its way (asked, not answered yet), else the one shown,
 * else null. It returns:
 * - {kind: 'keep', id}: that attempt is already shown or on its way;
 * - {kind: 'open', id}: read the attempt and follow it;
 * - {kind: 'redirect', id}: a finding already tried goes to its newest
 *   attempt (attempts is GET /fixes, newest first);
 * - {kind: 'finding', id}: a finding not started yet;
 * - {kind: 'none', id: ''}: nothing chosen.
 * @param {{attempt: string, finding: string}|null} route
 * @param {string|null} shownId
 * @param {object[]|null} attempts
 */
export function selectAction(route, shownId, attempts) {
  const r = route || { attempt: '', finding: '' }
  if (r.attempt) return { kind: r.attempt === shownId ? 'keep' : 'open', id: r.attempt }
  if (!r.finding) return { kind: 'none', id: '' }
  const tried = (attempts || []).find((a) => a?.finding?.id === r.finding)
  return tried ? { kind: 'redirect', id: tried.id } : { kind: 'finding', id: r.finding }
}

/**
 * acceptResult tells whether the answer for attempt id still counts: the
 * page is still there (alive) and id is the attempt it waits for (pending).
 * A late answer (the page left, or another attempt was asked since) is
 * dropped, so no stream is opened for a page that is gone.
 * @param {{alive: boolean, pending: string|null}} state
 * @param {string} id
 */
export function acceptResult(state, id) {
  return !!state && state.alive === true && state.pending === id
}
