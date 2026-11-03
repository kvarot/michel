// Pure functions behind the To-do page: one list, the most urgent first,
// projects and servers mixed. No DOM, no fetch, no storage. Vitest covers them
// (todoView.test.js).
import { translate } from '../i18n/index.js'
import { groupAttention, severityOf } from './digestView.js'
import { fixHash } from './fixView.js'
import { stripTechnicalIds } from './modeView.js'
import { findingTitle, mergeFindings, serversHash, touchedServers } from './serversView.js'

/** The most servers whose detail the page reads (ruling R15); the rest makes one line. */
export const maxServerDetails = 20

/** A server not checked for this long is old news, whatever its state says. */
const staleCheckMs = 7 * 24 * 3600 * 1000

const tones = { urgent: 'urgent', important: 'look', look: 'look', validate: 'info', finish: 'info' }

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
 * serversToRead are the servers whose detail the page asks for: those with
 * open flaws, the urgent ones first, at most maxServerDetails.
 * @param {object[]|null} servers GET /targets
 * @returns {object[]}
 */
export function serversToRead(servers) {
  return touchedServers(servers).slice(0, maxServerDetails)
}

/**
 * unseenBelow is what the page lists under the lines: the failed scans and an
 * old database have their own banners above them.
 * @param {{key: string, text: string}[]} unseen
 */
export function unseenBelow(unseen) {
  return (unseen || []).filter((u) => u.key !== 'failed_scans' && u.key !== 'osv_stale')
}

/** restoreNeeded mirrors ServerProposal.restoreNow: a package upgrade failed, or the site went down after it. */
function restoreNeeded(a) {
  const s = a.server
  if (!s || !s.needs_snapshot || a.state !== 'failed') return false
  return (s.steps || []).some((x) => (x.op === 'package_upgrade' || x.op === 'check_site') && !x.ok && x.detail !== 'not run')
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
 * read, and says so. Lines of equal rank keep their order of arrival: projects,
 * servers, then fixes.
 * @param {{digest: object, attempts: object[]|null, servers: object[]|null, details: Object<string, object>, lang: string, now: Date, advanced: boolean}} input
 * @returns {{head: string, sub: string, lines: {id: string, tone: string, word: string, title: string, where: string, action: {label: string, href: string}|null, rank: number}[], unseen: {key: string, text: string}[]}}
 */
export function buildTodo({ digest, attempts, servers, details, lang, now, advanced }) {
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
  ;(d.projects || []).forEach((p, i) => {
    const scope = `project:${p.name}`
    const where = inProject(p.name)
    const named = new Set(exploited.filter((e) => e.project === p.name).map((e) => e.finding_id))
    const rest = { ...(p.open || {}) }
    for (const item of groups[i]?.items || []) {
      if (item.kind === 'new') {
        // A decision to defer or ignore keeps it off the list until it is due.
        if (item.decided === 'ignore' || item.decided === 'defer') continue
        const ids = item.findingIds.filter((id) => !exploitedIds.has(id))
        const covered = item.findingIds.length > ids.length
        if (covered && !ids.length) continue
        const hot = !covered && (item.kev || item.malicious)
        const how = hot ? exploitedRank : bySeverity[severityOf(item.severity)]
        const title = item.text || t('todo.flaw', { package: item.package })
        const line = add(`new:${p.name}:${item.package}:${ids[0] || ''}`, how, title, item.kev && hot ? attacked(where) : where, how.action, fixHash({ finding: ids[0] || '' }), scope, ids)
        for (const id of line.ids) named.add(id)
        const sev = severityOf(item.severity)
        rest[sev] = Math.max(0, (rest[sev] || 0) - ids.length)
      } else if (item.kind === 'superseded') {
        const how = bySeverity[severityOf(item.severity)]
        const id = item.findingIds[0] || ''
        add(`superseded:${id}`, how, t('todo.superseded', { package: item.package }), where, how.action, fixHash({ finding: id }), scope, item.findingIds)
        named.add(id)
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
    // open has no row of its own, and must not vanish from the list.
    for (const a of newest) {
      if (a.server || a.project !== p.name || ['refused', 'superseded', 'proven_fixed'].includes(a.state) || a.finding?.status === 'gone') continue
      if (a.finding?.id && !named.has(a.finding.id)) {
        named.add(a.finding.id)
        const sev = severityOf(a.finding.severity)
        rest[sev] = Math.max(0, (rest[sev] || 0) - 1)
      }
    }
    const open = Object.values(p.open || {}).reduce((sum, n) => sum + (Number(n) || 0), 0)
    const remaining = open - (Number(p.decided?.defer) || 0) - named.size
    if (remaining > 0) {
      const worst = ['critical', 'high', 'medium', 'low'].find((s) => (Number(rest[s]) || 0) > 0) || 'unknown'
      add(`remaining:${p.name}`, bySeverity[worst], t('todo.remaining', { n: remaining }), where, 'see_all', fixHash(), scope)
    }
  })

  // Servers. A flaw counts only while it is new or pending, as openStatus in Go.
  const moreServers = []
  const readable = new Set(serversToRead(active).map((s) => s.id))
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
    const line = attemptLine(a, t)
    const fid = a.finding?.id || ''
    const hit = fid ? lines.find((l) => l.ids.includes(fid)) : null
    if (hit && !['refused', 'superseded'].includes(a.state) && !hit.linked) {
      hit.linked = true
      hit.action.href = line ? line.action.href : fixHash({ attempt: a.id })
    }
    if (!line) continue
    const made = { id: `fix:${a.id}`, ...line, ids: fid ? [fid] : [] }
    if (!hit) lines.push(made)
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
    return { head: t('todo.head.none'), sub: !unseen.length && looked ? t('todo.sub.looked', { what: looked }) : '', lines: out, unseen }
  }
  return { head: t('todo.head', { n: out.length }), sub: t('todo.sub.lines', { what: counted(projects, touched, t) }), lines: out, unseen }
}

/** counted says « 1 projet et 2 serveurs », leaving out what is zero. */
function counted(projects, servers, t) {
  const p = projects > 0 ? t('todo.sub.projects', { n: projects }) : ''
  const s = servers > 0 ? t('todo.sub.servers', { n: servers }) : ''
  return p && s ? t('todo.sub.both', { projects: p, servers: s }) : p || s
}

/** attemptLine is what a fix asks of the user, null when it asks nothing. */
function attemptLine(a, t) {
  const pkg = a.finding?.package || a.finding?.osv_id || ''
  const s = a.server
  const where = s ? t('todo.where.server', { name: s.target?.name || a.project }) : t('todo.where.project', { name: a.project })
  const scope = s ? `server:${s.target?.id || a.project}` : `project:${a.project}`
  const fix = fixHash({ attempt: a.id })
  const make = (rank, word, title, actionKey, href = fix) => ({ rank, word, title, where, action: { label: t(`todo.action.${actionKey}`), href }, scope })
  switch (a.state) {
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
      if (!s && a.finding?.status === 'gone') return null
      return make(4, 'look', t('todo.inconclusive', { package: pkg }), 'understand')
    case 'failed':
      if (restoreNeeded(a)) return make(0, 'urgent', t('todo.restore', { server: s?.target?.name || a.project }), 'check_server')
      if (a.finding?.status === 'gone') return null
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
