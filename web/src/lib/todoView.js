// Pure functions behind the To-do page: one list, the most urgent first,
// projects and servers mixed. No DOM, no fetch, no storage. Vitest covers them
// (todoView.test.js).
import { translate } from '../i18n/index.js'
import { groupAttention, localDay, severityOf, severityRank } from './digestView.js'
import { fixHash, isOpen } from './fixView.js'
import { stripTechnicalIds } from './modeView.js'
import { isVerified } from './pathView.js'
import { findingTitle, mergeFindings, restoreNeeded, serversHash, touchedServers } from './serversView.js'

/** The most servers whose detail the page reads (ruling R15); the rest makes one line. */
export const maxServerDetails = 20

/** A server not checked for this long is old news, whatever its state says. */
const staleCheckMs = 7 * 24 * 3600 * 1000

const tones = { urgent: 'urgent', important: 'look', look: 'look', validate: 'info', finish: 'info', yours: 'info' }

/** The words a line can carry. */
export const todoWords = Object.keys(tones)

/** @param {string} word one of todoWords @returns {'urgent'|'look'|'info'} a severity is always a colour and a word. */
export function toneOf(word) {
  return tones[word] || 'look'
}

/** What a severity makes of a flaw: its rank, its word, its action. */
const bySeverity = {
  critical: { rank: 1, word: 'urgent', action: 'solution' },
  high: { rank: 3, word: 'important', action: 'solution' },
  medium: { rank: 4, word: 'look', action: 'understand' },
  low: { rank: 5, word: 'look', action: 'solution' },
  unknown: { rank: 5, word: 'look', action: 'solution' },
}

const exploitedRank = { rank: 0, word: 'urgent', action: 'solution' }

/**
 * serversToRead are the servers whose detail the page asks for, at most
 * maxServerDetails: those with open flaws, the urgent ones first, then those
 * checked with none. Only its detail tells what a clean server could not judge.
 * @param {object[]|null} servers GET /targets
 * @returns {object[]}
 */
export function serversToRead(servers) {
  return [...touchedServers(servers), ...cleanServers(servers)].slice(0, maxServerDetails)
}

/** cleanServers are the active servers checked, with no open flaw. */
function cleanServers(servers) {
  return (Array.isArray(servers) ? servers : []).filter((s) => s && s.active !== false && s.state?.code === 'clean' && !(Number(s.open_findings) > 0))
}

/** openCount is what the digest counts as open in a project, without what is deferred. */
function openCount(p) {
  const open = Object.values(p.open || {}).reduce((sum, n) => sum + (Number(n) || 0), 0)
  return open - (Number(p.decided?.defer) || 0)
}

/**
 * projectsToRead are the projects whose findings the page asks for: the digest
 * names only what is new in its window, and only the list says what else is
 * open. A project whose fix went nowhere on a decided flaw is read too: only
 * the list says what was decided.
 * @param {object|null} digest GET /today
 * @param {object[]|null} attempts GET /fixes
 * @returns {object[]}
 */
export function projectsToRead(digest, attempts) {
  const tried = new Set((attempts || [])
    .filter((a) => a && !a.server && a.finding?.status === 'decided' && ['failed', 'inconclusive'].includes(a.state))
    .map((a) => a.project))
  return (digest?.projects || []).filter((p) => openCount(p) > 0 || tried.has(p.name))
}

/** findingName is what a finding's line calls it: its package, or the tool for a tool's finding (scan.Ref). */
export function findingName(f) {
  if (f.kind && f.kind !== 'dependency') return String(f.source_key || '').replace(/^plugin\./, '') || f.rule_id || f.package
  return f.package || f.osv_id
}

/**
 * flawTitle is the sentence of a line of the list. A tool's finding touches no
 * package: the tool found it, the flaw does not touch the tool.
 * @param {string} name findingName or the digest's name of the line
 * @param {string} kind the kind of the finding
 * @param {string} lang
 * @returns {string}
 */
function flawTitle(name, kind, lang) {
  return kind && kind !== 'dependency' ? translate(lang, 'todo.flaw_tool', { tool: name }) : translate(lang, 'todo.flaw', { package: name })
}

/**
 * guideTitle is the heading of a flaw's page. An attempt's finding has neither
 * the kind nor the tool: a flaw without a package keeps one plain sentence, so
 * the heading does not change when the sheet comes.
 * @param {object} finding the list's or the attempt's finding
 * @param {object|null} sheet GET /findings/{id}
 * @param {string} lang
 * @returns {string}
 */
export function guideTitle(finding, sheet, lang) {
  const f = sheet || finding || {}
  const name = f.package || f.kind === 'dependency' ? findingName(f) : ''
  return name ? translate(lang, 'todo.flaw', { package: name }) : translate(lang, 'path.title_any')
}

const isHot = (f) => !!(f.kev || f.malicious)

/** worstOf is the most severe severity of findings. */
function worstOf(list) {
  return list.map((f) => severityOf(f.severity)).sort((a, b) => severityRank(a) - severityRank(b))[0]
}

/**
 * unseenBelow is what the page lists under the lines: the failed scans and an
 * old database have their own banners above them.
 * @param {{key: string, text: string}[]} unseen
 */
export function unseenBelow(unseen) {
  return (unseen || []).filter((u) => u.key !== 'failed_scans' && u.key !== 'osv_stale')
}

/** newestByFinding keeps a finding's newest attempt; GET /fixes lists the newest first. */
function newestByFinding(attempts) {
  const seen = new Set()
  const out = []
  for (const a of attempts || []) {
    const id = a?.finding?.id || ''
    if (!a || seen.has(id)) continue
    seen.add(id)
    out.push(a)
  }
  return out
}

/** @returns {boolean} whether the digest's time means no database was ever fetched. */
function noDate(t) {
  return !t || String(t).startsWith('0001-')
}

/**
 * buildTodo makes the To-do page: the head, a sentence under it, the lines,
 * and what Michel did not see. It never says that all is well: an empty list
 * only says « as far as Michel could see », followed by what he could not.
 * attempts or servers null means the page could not read them. details maps a
 * server id to GET /targets/{id}; a touched server missing from it could not be
 * read, and says so. findings maps a project's name to GET
 * /projects/{name}/findings, null when it could not be read; a project with
 * something open and no list says so too, with a count that may be too high.
 * Lines of equal rank keep their order of arrival: projects, servers, then fixes.
 * @param {{digest: object, attempts: object[]|null, servers: object[]|null, details: Object<string, object>, findings: Object<string, object[]|null>, lang: string, now: Date, advanced: boolean}} input
 * @returns {{head: string, sub: string, lines: {id: string, tone: string, word: string, title: string, where: string, action: {label: string, href: string}|null, rank: number}[], unseen: {key: string, text: string}[]}}
 */
export function buildTodo({ digest, attempts, servers, details, findings, lang, now, advanced }) {
  const t = (key, params) => translate(lang, key, params)
  const d = digest || {}
  const active = (servers || []).filter((s) => s && s.active !== false)
  const lines = []
  // scope names what a line touches, for the sentence under the head.
  const add = (id, how, title, where, actionKey, href, scope, ids = []) => {
    const line = { id, rank: how.rank, word: how.word, title, where, action: { label: t(`todo.action.${actionKey}`), href }, scope, ids }
    lines.push(line)
    return line
  }
  const inProject = (name) => t('todo.where.project', { name })
  const onServer = (name) => t('todo.where.server', { name })
  const attacked = (where) => `${where} ${t('todo.where.exploited')}`

  // Projects: every exploited flaw first, whatever the digest's window.
  const exploited = d.exploited || []
  const exploitedIds = new Set(exploited.map((e) => e.finding_id))
  for (const e of exploited) {
    const title = t(e.malicious ? 'todo.malicious' : 'todo.exploited', { package: e.package })
    const shown = advanced && e.osv_id ? `${title} (${e.osv_id})` : title
    const where = e.malicious ? inProject(e.project) : attacked(inProject(e.project))
    add(`exploited:${e.finding_id}`, exploitedRank, shown, where, 'solution', fixHash({ finding: e.finding_id }), `project:${e.project}`, [e.finding_id])
  }

  const newest = newestByFinding(attempts)
  const groups = groupAttention(d)
  const known = new Map()
  ;(d.projects || []).forEach((p, i) => {
    const scope = `project:${p.name}`
    const where = inProject(p.name)
    const list = Array.isArray(findings?.[p.name]) ? findings[p.name].filter(Boolean) : null
    for (const f of list || []) known.set(f.id, f)
    const closed = (id) => known.has(id) && !isOpen(known.get(id))
    for (const item of groups[i]?.items || []) {
      if (item.kind === 'new') {
        // A decision to defer or ignore keeps it off the list until it is due.
        if (item.decided === 'ignore' || item.decided === 'defer') continue
        const covered = item.findingIds.some((id) => exploitedIds.has(id))
        // A row may hold a flaw already decided: the list says which are left.
        const ids = item.findingIds.filter((id) => !exploitedIds.has(id) && !closed(id))
        if (item.findingIds.length && !ids.length) continue
        const seen = ids.every((id) => known.has(id)) ? ids.map((id) => known.get(id)) : []
        const hot = !covered && (seen.length ? seen.some(isHot) : item.kev || item.malicious)
        const kev = seen.length ? seen.some((f) => f.kev) : item.kev
        const how = hot ? exploitedRank : bySeverity[seen.length ? worstOf(seen) : severityOf(item.severity)]
        // The explanation names a version and a file: for the advanced mode.
        const title = advanced && item.text ? item.text : flawTitle(item.package, item.findingKind, lang)
        add(`new:${p.name}:${item.package}:${ids[0] || ''}`, how, title, kev && hot ? attacked(where) : where, how.action, fixHash({ finding: ids[0] || '' }), scope, ids)
      } else if (item.kind === 'superseded') {
        const id = item.findingIds[0] || ''
        if (exploitedIds.has(id)) continue
        const how = bySeverity[severityOf(item.severity)]
        add(`superseded:${id}`, how, t('todo.superseded', { package: item.package }), where, how.action, fixHash({ finding: id }), scope, item.findingIds)
      } else if (item.kind === 'due' && (item.overdue || Date.parse(item.text) <= now.getTime())) {
        const how = bySeverity[severityOf(item.severity)]
        const id = item.findingIds[0] || ''
        add(`due:${id}`, how, t('todo.due', { package: item.package }), where, how.action, fixHash({ finding: id }), scope, item.findingIds)
      }
    }
    if (p.last_scan_status === 'failed' || p.last_scan_status === 'interrupted') {
      add(`scan:${p.name}`, bySeverity.low, t('todo.scan_failed'), where, 'see_project', '#/projects', scope)
    }

    // The digest names only what is new in its window: an older flaw still
    // open has no row of its own. The list names it, by package and severity.
    if (list) {
      const carried = new Set(lines.flatMap((l) => l.ids))
      const rows = new Map()
      for (const f of list) {
        if (!isOpen(f) || carried.has(f.id)) continue
        const key = [f.ecosystem, f.source_key, findingName(f), severityOf(f.severity)].join('|')
        if (!rows.has(key)) rows.set(key, [])
        rows.get(key).push(f)
      }
      for (const row of rows.values()) {
        const hot = row.some(isHot)
        const how = hot ? exploitedRank : bySeverity[severityOf(row[0].severity)]
        const said = row.some((f) => f.kev) ? attacked(where) : where
        add(`open:${p.name}:${row[0].id}`, how, flawTitle(findingName(row[0]), row[0].kind, lang), said, how.action, fixHash({ finding: row[0].id }), scope, row.map((f) => f.id))
      }
    } else if (openCount(p) > 0) {
      // The count may name what a line already says: too high rather than too low.
      const worst = ['critical', 'high', 'medium', 'low'].find((s) => Number(p.open?.[s]) > 0) || 'unknown'
      add(`unread:${p.name}`, bySeverity[worst], t('todo.project_unread', { n: openCount(p) }), where, 'see_project', '#/projects', scope)
    }
  })

  // Servers. A flaw counts only while it is new or pending, as openStatus in Go.
  const moreServers = []
  // A clean server is read too, but has no flaw to say: a failed read is only a note.
  const readable = new Set(touchedServers(active).slice(0, maxServerDetails).map((s) => s.id))
  for (const s of active) {
    const scope = `server:${s.id}`
    const where = onServer(s.name)
    const code = s.state?.code
    if (readable.has(s.id)) {
      const detail = details?.[s.id]
      if (!detail) {
        const n = Number(s.open_findings) || 0
        const how = Number(s.urgent_open) > 0 ? exploitedRank : Number(s.critical_open) > 0 ? bySeverity.critical : { rank: 4, word: 'look' }
        add(`unread:${s.id}`, how, t('todo.server_unread', { server: s.name, n }), where, 'see_server', serversHash(s.id), scope)
      } else {
        const open = (detail.findings || []).filter((f) => f && (f.status === 'new' || f.status === 'pending'))
        for (const card of mergeFindings(open, null)) {
          const f = card.finding
          const members = open.filter((x) => card.ids.includes(x.id))
          const hot = members.some((x) => x.urgent || x.kev)
          const kev = members.some((x) => x.kev)
          const href = serversHash(s.id, f.id)
          const id = `server:${s.id}:${f.id}`
          if (f.kind === 'server_exposure') {
            const title = t(f.rule === 'exposed_cache' ? 'todo.exposure_cache' : 'todo.exposure')
            add(id, { rank: 4, word: 'look' }, title, where, 'understand', href, scope, card.ids)
            continue
          }
          const how = hot ? exploitedRank : bySeverity[severityOf(f.severity)]
          const title = f.kind === 'server_package' && !advanced ? t('todo.server_package', { server: s.name }) : findingTitle(f, lang)
          add(id, how, title, kev ? attacked(where) : where, how.action, href, scope, card.ids)
        }
      }
    } else if (Number(s.open_findings) > 0) {
      moreServers.push(s)
    }
    if (Number(s.log_new) > 0) {
      add(`logs:${s.id}`, bySeverity.low, t('todo.log_new', { n: Number(s.log_new), server: s.name }), where, 'see_errors', serversHash(s.id), scope)
    }
    if (code === 'key_unconfirmed') {
      add(`key:${s.id}`, bySeverity.low, t('todo.key_unconfirmed', { server: s.name }), where, 'confirm_key', serversHash(s.id), scope)
    }
    if (code === 'check_failed') {
      const said = advanced && s.state?.text ? `${where} ${s.state.text}` : where
      add(`check:${s.id}`, bySeverity.low, t('todo.check_failed', { server: s.name }), said, 'see_check', serversHash(s.id), scope)
    }
  }
  if (moreServers.length) {
    const how = moreServers.some((s) => Number(s.urgent_open) > 0) ? exploitedRank
      : moreServers.some((s) => Number(s.critical_open) > 0) ? bySeverity.critical : { rank: 4, word: 'look' }
    add('servers:more', how, t('todo.more_servers', { n: moreServers.length }), t('todo.where.servers'), 'see_servers', serversHash(''), 'servers:more')
  }

  // Fixes. A flaw with a line keeps one line: the most urgent of the two says
  // it, and the action opens the fix.
  for (const a of newest) {
    const line = attemptLine(a, t, known)
    const fid = a.finding?.id || ''
    const hit = fid ? lines.find((l) => l.ids.includes(fid)) : null
    const taken = !!hit?.linked
    if (hit && !['refused', 'superseded'].includes(a.state) && !taken) {
      hit.linked = true
      hit.action.href = line ? line.action.href : fixHash({ attempt: a.id })
    }
    if (!line) continue
    const made = { id: `fix:${a.id}`, ...line, ids: fid ? [fid] : [] }
    // A line that opens another fix keeps it: this one is said on its own.
    if (!hit || taken) lines.push(made)
    else if (made.rank <= hit.rank) Object.assign(hit, { rank: made.rank, word: made.word, title: made.title, where: made.where, action: made.action, scope: made.scope })
  }

  const out = lines
    .map((l, i) => ({ l, i }))
    .sort((a, b) => a.l.rank - b.l.rank || a.i - b.i)
    .map(({ l }) => ({
      id: l.id, tone: toneOf(l.word), word: t(`todo.word.${l.word}`), title: advanced ? l.title : stripTechnicalIds(l.title), where: l.where, action: l.action, rank: l.rank,
    }))
  const unseen = seenNot(d, servers, attempts, active, details, now, t)
  const scopes = new Set(lines.map((l) => l.scope))
  const projects = [...scopes].filter((s) => s.startsWith('project:')).length
  const touched = [...scopes].filter((s) => s.startsWith('server:')).length + moreServers.length
  if (!out.length) {
    const looked = counted((d.projects || []).length, active.length, t)
    const busy = unseen.some((u) => u.key === 'in_progress')
    return { head: t(busy ? 'todo.head.checking' : unseen.length ? 'todo.head.unseen' : 'todo.head.none'), sub: !unseen.length && looked ? t('todo.sub.looked', { what: looked }) : '', lines: out, unseen }
  }
  return { head: t('todo.head', { n: out.length }), sub: t('todo.sub.lines', { what: counted(projects, touched, t) }), lines: out, unseen }
}

/** counted says « 1 projet et 2 serveurs », leaving out what is zero. */
function counted(projects, servers, t) {
  const p = projects > 0 ? t('todo.sub.projects', { n: projects }) : ''
  const s = servers > 0 ? t('todo.sub.servers', { n: servers }) : ''
  return p && s ? t('todo.sub.both', { projects: p, servers: s }) : p || s
}

/** attemptLine is what a fix asks of the user, null when it asks nothing. known maps a project's finding id to its FindingView. */
function attemptLine(a, t, known) {
  const pkg = a.finding?.package || a.finding?.osv_id || ''
  const s = a.server
  const where = s ? t('todo.where.server', { name: s.target?.name || a.project }) : t('todo.where.project', { name: a.project })
  const scope = s ? `server:${s.target?.id || a.project}` : `project:${a.project}`
  const fix = fixHash({ attempt: a.id })
  // A flaw decided since: a server has no other word for it, a project says which decision.
  const settled = s ? a.finding?.status === 'decided' : ['ignore', 'defer'].includes(known.get(a.finding?.id)?.decision?.action)
  const make = (rank, word, title, actionKey, href = fix) => ({ rank, word, title, where, action: { label: t(`todo.action.${actionKey}`), href }, scope })
  switch (a.state) {
    case 'held':
      // The agent does not start and the project is taken until the person answers.
      return make(2, 'yours', t('todo.held', { n: a.hold?.count ?? 0 }), 'answer')
    case 'proposed':
      return make(2, 'validate', t('todo.proposed', { package: pkg }), 'validate')
    case 'approved':
      // Michel runs it by himself, except when the user keeps the script.
      return s && s.executor === 'user' ? make(2, 'finish', t('todo.run_script'), 'finish') : null
    case 'unknown':
      return make(0, 'urgent', t('todo.unknown', { server: s?.target?.name || a.project }), 'check_server')
    case 'applied':
      // Only a project's fix has a branch to merge: the API fills branch for a server too.
      if (s) return make(5, 'look', t('todo.applied_server', { server: s.target?.name || a.project }), 'see_server', serversHash(s.target?.id, a.finding?.id))
      return make(2, 'finish', t('todo.applied'), 'finish')
    case 'inconclusive':
      // A project's flaw that is gone leaves nothing to do; on a server, the site may be down.
      if ((!s && a.finding?.status === 'gone') || settled) return null
      return make(4, 'look', t('todo.inconclusive', { package: pkg }), 'understand')
    case 'failed':
      if (restoreNeeded(a)) return make(0, 'urgent', t('todo.restore', { server: s?.target?.name || a.project }), 'check_server')
      if (a.finding?.status === 'gone' || settled) return null
      return make(4, 'look', t('todo.failed', { package: pkg }), 'understand')
    default:
      return null
  }
}

/** seenNot lists what Michel could not see, or the page could not read. Names only, never a log line nor a reason. */
function seenNot(d, servers, attempts, active, details, now, t) {
  const out = []
  const note = (key, textKey, params) => out.push({ key, text: t(textKey, params) })
  const projects = d.projects || []
  const names = (list) => list.map((x) => x.name).join(', ')
  const byStatus = (status) => projects.filter((p) => p.last_scan_status === status)

  if (!projects.length && servers && !active.length) note('nothing', 'todo.unseen.nothing')
  if (Number(d.failed_scans) > 0) note('failed_scans', 'today.failed_scans', { n: Number(d.failed_scans) })
  const never = byStatus('never')
  if (never.length) note('never_scanned', 'todo.unseen.never_scanned', { n: never.length, names: names(never) })
  const partial = byStatus('partial')
  if (partial.length) note('partial', 'todo.unseen.partial', { n: partial.length, names: names(partial) })
  const empty = byStatus('empty')
  if (empty.length) note('empty', 'todo.unseen.empty', { n: empty.length, names: names(empty) })
  if (d.osv_stale) note('osv_stale', 'todo.unseen.osv_stale')
  else if (noDate(d.osv_fetched_at)) note('no_db', 'todo.unseen.no_db')

  const code = (s) => s.state?.code
  const running = [...byStatus('running'), ...active.filter((s) => code(s) === 'checking')]
  if (running.length) note('in_progress', 'todo.unseen.in_progress', { names: names(running) })
  const notYet = active.filter((s) => code(s) === 'never_checked' || code(s) === 'key_unconfirmed')
  if (notYet.length) note('server_never', 'todo.unseen.server_never', { n: notYet.length, names: names(notYet) })
  const failed = active.filter((s) => code(s) === 'check_failed')
  if (failed.length) note('server_failed', 'todo.unseen.server_failed', { n: failed.length, names: names(failed) })
  // A server with open flaws says « findings »: only its detail tells what was not read.
  const unread = active.filter((s) => {
    const detail = details?.[s.id]
    return code(s) === 'unread' || (detail && ((detail.unseen || []).length > 0 || !!detail.source_to_enable))
  })
  if (unread.length) note('server_unread', 'todo.unseen.server_unread', { n: unread.length, names: names(unread) })
  const notRead = cleanServers(active).filter((s) => !details?.[s.id])
  if (notRead.length) note('server_not_read', 'todo.unseen.server_not_read', { names: names(notRead) })
  const old = active.filter((s) => {
    if (notYet.includes(s) || failed.includes(s) || !s.last_check_at) return false
    const at = Date.parse(s.last_check_at)
    return !Number.isNaN(at) && now.getTime() - at > staleCheckMs
  })
  if (old.length) note('server_stale', 'todo.unseen.server_stale', { n: old.length, names: names(old) })
  const logs = (d.server_logs || []).filter((l) => (l.gaps || []).length > 0 || Number(l.skipped) > 0)
  if (logs.length) note('logs', 'todo.unseen.logs', { names: names(logs) })

  if (servers === null) note('servers_unread', 'todo.unseen.servers_unread')
  if (attempts === null) note('fixes_unread', 'todo.unseen.fixes_unread')
  return out
}

/**
 * resolvedLines makes the lines of the Resolved page, the newest on top. An
 * attempt is listed only when the proof ran (state proven_fixed); it is
 * verified only under ruling R2 (isVerified): a project's fix with no clean
 * new scan of the copy is listed apart, as fixed and not confirmed, and a flaw
 * that is no longer gone is listed as back (back), never as verified. The date
 * is the local day of the attempt's updated_at, which the proof sets last. exposures are the
 * services that a full reading no longer sees open to all (closedExposures):
 * never a fix and never verified, the service may have moved or stopped (R47),
 * and their date is the last time Michel saw them open.
 * @param {object[]|null} attempts GET /fixes?state=proven_fixed
 * @param {{server: {id: string, name: string}, service: string, at: string}[]|null} exposures
 * @param {string} lang
 * @returns {{at: string, dateKey: string, word: string, tone: string, title: string, where: string, verified: boolean, back: boolean, href: string, deploy: boolean, kind: string}[]}
 */
export function resolvedLines(attempts, exposures, lang) {
  const t = (key, params) => translate(lang, key, params)
  const out = []
  const stamp = (iso) => {
    const ms = Date.parse(iso)
    return Number.isNaN(ms) ? 0 : ms
  }
  for (const a of attempts || []) {
    if (!a || a.state !== 'proven_fixed') continue
    const s = a.server
    const pkg = a.finding?.package || a.finding?.osv_id || ''
    // back: the flaw is seen again although the proof once ran.
    const back = !!a.finding?.status && a.finding.status !== 'gone'
    const verified = isVerified(a)
    out.push({
      at: localDay(a.updated_at, lang),
      dateKey: 'resolved.date',
      word: back ? 'back' : verified ? 'verified' : 'unconfirmed',
      tone: verified ? 'done' : 'look',
      title: t(back ? 'resolved.line_back' : 'resolved.line', { package: pkg }),
      back,
      where: s ? t('todo.where.server', { name: s.target?.name || a.project }) : t('todo.where.project', { name: a.project }),
      verified,
      href: s ? serversHash(s.target?.id, a.finding?.id) : fixHash({ attempt: a.id }),
      deploy: !s,
      kind: s ? 'server' : 'project',
      sort: stamp(a.updated_at),
    })
  }
  for (const e of exposures || []) {
    if (!e) continue
    const named = e.service === 'database' || e.service === 'cache'
    out.push({
      at: localDay(e.at, lang),
      dateKey: 'resolved.exposure_date',
      word: 'no_longer_open',
      tone: 'info',
      back: false,
      title: t(named ? `resolved.exposure_${e.service}` : 'resolved.exposure'),
      where: t('todo.where.server', { name: e.server?.name || '' }),
      verified: false,
      href: serversHash(e.server?.id),
      deploy: false,
      kind: 'exposure',
      sort: stamp(e.at),
    })
  }
  return out.sort((a, b) => b.sort - a.sort).map(({ sort, ...line }) => line)
}
