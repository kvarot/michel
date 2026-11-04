// Pure functions behind the first steps guide: no DOM, no fetch. Storage comes
// in as a function, and only holds "skipped" and "a flaw was read": where the
// person stands is read from the data, so an emptied or blocked storage changes
// nothing but those two. Vitest covers them (guideView.test.js).
import { keys } from './storage.js'
import { runsHere } from './projectsView.js'
import { serversHash } from './serversView.js'

// The last check read something: a partial one or an empty folder is said elsewhere (todo.unseen).
const checkedStatuses = ['ok', 'partial', 'empty']
const checkedStates = ['clean', 'findings', 'unread']

/**
 * readGuide reads what the storage keeps. Absent, invalid, or a storage that
 * throws: both false.
 * @param {(key: string) => string} load
 * @returns {{dismissed: boolean, read: boolean}}
 */
export function readGuide(load) {
  try {
    const v = JSON.parse(load(keys.guide) || 'null')
    return { dismissed: v?.dismissed === true, read: v?.read === true }
  } catch {
    return { dismissed: false, read: false }
  }
}

/** write keeps the two facts; a storage that refuses leaves them for this visit. */
function write(state, save) {
  try {
    save(keys.guide, JSON.stringify({ dismissed: !!state.dismissed, read: !!state.read }))
  } catch {
    // Nothing to do: the state lives on in memory until the page is closed.
  }
}

/** markGuideRead notes that a flaw was shown to the person. */
export function markGuideRead(state, save) {
  if (state.read) return
  state.read = true
  write(state, save)
}

/** dismissGuide is "Ignorer pour l'instant". */
export function dismissGuide(state, save) {
  state.dismissed = true
  state.again = false
  write(state, save)
}

/** showGuideAgain is "Revoir le guide": asks grows at each request, again lasts until the page closes. */
export function showGuideAgain(state, save) {
  state.dismissed = false
  state.again = true
  state.asks = (Number(state.asks) || 0) + 1
  write(state, save)
}

/**
 * guideWaiting: a check runs here and now. A project row that says "running"
 * alone may belong to another window, or to a process that died: it is not
 * waited for (see runsHere), and the guide offers the check again.
 * @param {object[]} projects
 * @param {object[]} servers
 * @returns {{href: string}|null} where to follow it, null when nothing runs
 */
export function guideWaiting(projects, servers) {
  if ((projects || []).some((p) => p && runsHere(p))) return { href: '#/projects' }
  const server = (servers || []).find((s) => s?.state?.code === 'checking')
  return server ? { href: serversHash(server.id) } : null
}

/** projectFailed: the last check of this project did not end. */
function projectFailed(p) {
  return !p.scanning && (!!p.last_failure || p.last_scan_status === 'failed')
}

/**
 * checkStep says what step two holds: where to go, or that a check runs.
 * Projects first: their button is on a page of its own, a server has its sheet.
 */
function checkStep(projects, servers) {
  const waiting = guideWaiting(projects, servers)
  if (waiting) return { text: 'guide.check.running', action: { label: 'guide.check.action_follow', href: waiting.href } }
  const failedProject = projects.some(projectFailed)
  if (failedProject) return { text: 'guide.check.failed', action: { label: 'guide.check.action_failed', href: '#/projects' } }
  if (projects.length) return { text: 'guide.check.text', action: { label: 'guide.check.action', href: '#/projects' } }
  const failedServer = servers.find((s) => s.state?.code === 'check_failed')
  if (failedServer) return { text: 'guide.check.failed', action: { label: 'guide.check.action_failed', href: serversHash(failedServer.id) } }
  if (servers.length) return { text: 'guide.check.text', action: { label: 'guide.check.action_server', href: serversHash(servers[0].id) } }
  return { text: 'guide.check.text', action: null }
}

/**
 * guideSteps are the three steps, read from the data. Only the current step
 * offers an action, and label is a key of the catalog. Without a flaw, step three
 * stays open and says so: done would be a claim, and the guide would vanish before
 * the sentence is read.
 * @param {{projects: object[], servers: object[], read: boolean, anyFinding: boolean, flawHref?: string}} input
 *   projects is GET /projects, servers GET /targets.
 * @returns {{key: 'add'|'check'|'read', done: boolean, current: boolean, text: string, action: {label: string, href: string}|null}[]}
 */
export function guideSteps({ projects, servers, read, anyFinding, flawHref = '' }) {
  const ps = (projects || []).filter(Boolean)
  const ss = (servers || []).filter(Boolean)
  const added = ps.length > 0 || ss.length > 0
  const checked = ps.some((p) => checkedStatuses.includes(p.last_scan_status)) || ss.some((s) => checkedStates.includes(s.state?.code))
  const check = checkStep(ps, ss)
  const seesNothing = checked && !anyFinding
  const steps = [
    { key: 'add', done: added, text: 'guide.add.text', action: { label: 'guide.add.action', href: '#/projects' } },
    { key: 'check', done: checked, text: check.text, action: check.action },
    {
      key: 'read',
      done: !!read,
      text: seesNothing ? 'guide.read.none' : 'guide.read.text',
      action: anyFinding ? { label: 'guide.read.action', href: flawHref || '#/' } : null,
    },
  ]
  const current = steps.findIndex((s) => !s.done)
  return steps.map((s, i) => ({ ...s, current: i === current, action: i === current ? s.action : null }))
}

/**
 * guideVisible: asked for again, always; skipped, never; else while a step is left.
 * @param {{done: boolean}[]} steps
 * @param {{dismissed?: boolean, again?: boolean}} state
 * @returns {boolean}
 */
export function guideVisible(steps, state) {
  if (state?.again) return true
  if (state?.dismissed) return false
  return steps.some((s) => !s.done)
}

/**
 * guideGitQuestion names the project to ask about, from the stored answers: the
 * first with a repository and no answer, else the first without a repository,
 * which is told why nothing is asked. It never holds up a step.
 * @param {object[]|null} projects GET /projects
 * @returns {{name: string, mode: 'ask'|'no_repo'}|null}
 */
export function guideGitQuestion(projects) {
  const open = (projects || []).filter((p) => p && !p.git_answer)
  const ask = open.find((p) => p.git_repo)
  if (ask) return { name: ask.name, mode: 'ask' }
  const bare = open.find((p) => !p.git_repo)
  return bare ? { name: bare.name, mode: 'no_repo' } : null
}

/** openNow is what a project counts as open, without what is deferred. */
function openNow(p) {
  const open = Object.values(p.open || {}).reduce((sum, n) => sum + (Number(n) || 0), 0)
  return open - (Number(p.decided?.defer) || 0)
}

/**
 * guideFlaw says whether there is a flaw to read, and where: the first line of
 * the list that is a flaw (the most urgent), else the place that counts one.
 * @param {{lines: {action: {href: string}|null}[], projects: object[], servers: object[]}} input
 * @returns {{any: boolean, href: string}}
 */
export function guideFlaw({ lines, projects, servers }) {
  const line = (lines || []).find((l) => l?.flaw && l.action?.href)
  if (line) return { any: true, href: line.action.href }
  if ((projects || []).some((p) => p && openNow(p) > 0)) return { any: true, href: '#/projects' }
  const server = (servers || []).find((s) => s && Number(s.open_findings) > 0)
  if (server) return { any: true, href: serversHash(server.id) }
  return { any: false, href: '' }
}

/**
 * emptyInstall: nothing to watch yet, and both lists were read to say so.
 * @param {object[]|null} projects
 * @param {object[]|null} servers
 * @returns {boolean}
 */
export function emptyInstall(projects, servers) {
  return Array.isArray(projects) && Array.isArray(servers) && !projects.length && !servers.length
}

/**
 * guideUnseen: the sentences under the list. On an empty install the title
 * already says "nothing watched", so that one is not said twice.
 * @param {{key: string}[]} unseen
 * @param {boolean} nothingWatched
 */
export function guideUnseen(unseen, nothingWatched) {
  return nothingWatched ? unseen.filter((u) => u.key !== 'nothing') : unseen
}

/**
 * helpLostNow says « Michel n'a pas pu lire tes projets ou tes serveurs » is true now: the
 * guide was asked for, it is not shown, the first reading ended (before that the lists are
 * only loading), and a list could not be read. Once both read, the line has no case.
 * @param {{asked: boolean, loaded: boolean, guideShown: boolean, projectViews: object|null, servers: object|null}} args
 * @returns {boolean}
 */
export function helpLostNow({ asked, loaded, guideShown, projectViews, servers }) {
  return !!asked && !!loaded && !guideShown && (!projectViews || !servers)
}
