// Pure functions behind the My projects page: no DOM, no fetch, no storage.
// Vitest covers them (projectsView.test.js).
import { translate } from '../i18n/index.js'
import { agoText } from './sourcesView.js'

/**
 * cleanProjectPath is the path as it goes to Michel: without the spaces and the
 * quotes a "copy as path" leaves around it.
 * @param {string} [path]
 * @returns {string}
 */
export function cleanProjectPath(path) {
  return String(path ?? '').trim().replace(/^(["'])(.*)\1$/, '$2').trim()
}

/**
 * projectNameFromPath proposes a name: the last folder of a Windows or Unix
 * path, "" for a disk or nothing.
 * @param {string} [path]
 * @returns {string}
 */
export function projectNameFromPath(path) {
  const parts = cleanProjectPath(path).split(/[\\/]+/).filter(Boolean)
  const last = parts[parts.length - 1] || ''
  return /^[a-zA-Z]:$/.test(last) ? '' : last
}

/** @param {{scanning?: boolean, last_failure?: object|null}} project @returns {boolean} the last check failed and no new one runs. */
export function showsFailure(project) {
  return !project.scanning && !!project.last_failure
}

/**
 * checkedWell tells whether the last check read the whole project. Only then
 * may a card say "0 critical flaw": before, or after a failed or partial check,
 * 0 means that Michel did not see, not that nothing is there.
 * The counts come from the digest and the status from GET /projects: until the
 * digest read after the check has arrived (digestFresh), 0 is only the old count.
 * @param {{scanning?: boolean, last_failure?: object|null, last_scan_status?: string}} project
 * @param {boolean} [digestFresh]
 * @returns {boolean}
 */
export function checkedWell(project, digestFresh) {
  return digestFresh === true && !project.scanning && !project.last_failure && project.last_scan_status === 'ok'
}

/**
 * runsHere tells a check this Michel is running now. A status "running" alone is
 * a row in the database: its process may be another window, or dead.
 * @param {{scanning?: boolean}} project
 * @returns {boolean}
 */
export function runsHere(project) {
  return !!project.scanning
}

/**
 * needsDigest tells whether the digest must be read again, now that nothing
 * runs: a check was seen running, a click is waiting for its result, or this is
 * the first look of the page, which cannot know what ended while it was away.
 * @param {object[]|null} previous the last views
 * @param {object[]|null} list the views just read
 * @param {boolean} awaiting a click on a check has not been followed yet
 * @param {boolean} firstLoad
 * @returns {boolean}
 */
export function needsDigest(previous, list, awaiting, firstLoad) {
  if (anyScanning(list)) return false
  return anyScanning(previous) || awaiting || firstLoad
}

/**
 * scanHintKey is what a card proposes after a check that is not whole. Starting
 * again changes nothing for a damaged file or a source turned off.
 * @param {string} [status]
 * @returns {string}
 */
export function scanHintKey(status) {
  return status === 'partial' ? 'project.scan.partial_hint' : 'project.scan_hint'
}

/**
 * scanSentence says where the checks of a project stand, in one sentence. It
 * says what Michel did, never that the project is safe.
 * @param {{scanning?: boolean, last_failure?: {error: string}|null, last_scan_status?: string, last_scan_at?: string}} project
 * @param {string} lang
 * @param {Date} [now]
 * @returns {string}
 */
export function scanSentence(project, lang, now = new Date()) {
  const t = (key, params) => translate(lang, key, params)
  if (project.scanning) return t('project.scan.running')
  if (showsFailure(project)) return project.last_failure.error
  switch (project.last_scan_status) {
    case 'running':
      return t('project.scan.elsewhere')
    case 'ok': {
      const ago = agoText(project.last_scan_at, now, t)
      return ago ? t('project.scan.ok', { ago }) : t('project.scan.done')
    }
    case 'failed':
    case 'interrupted':
    case 'partial':
    case 'empty':
      return t(`project.scan.${project.last_scan_status}`)
    default:
      return t('project.scan.never')
  }
}

/**
 * withScanState joins to a project of the digest how its check stands
 * (GET /projects). The digest stays the source of everything else.
 * @param {object} project
 * @param {object} [view]
 * @returns {object}
 */
export function withScanState(project, view) {
  if (!view) return project
  return {
    ...project,
    scanning: !!view.scanning,
    last_failure: view.last_failure || null,
    last_scan_at: view.last_scan_at || '',
    last_scan_status: view.last_scan_status || project.last_scan_status,
  }
}

/** @param {{scanning?: boolean, last_scan_status?: string}[]|null} views @returns {boolean} a check is running somewhere, here or in another window: the page keeps looking. */
export function anyScanning(views) {
  return (views || []).some((v) => v.scanning || v.last_scan_status === 'running')
}

/** @param {string} name @param {string} lang @returns {string} the API path that starts the check of a project. */
export function scanPath(name, lang) {
  return `/projects/${encodeURIComponent(name)}/scan?lang=${encodeURIComponent(lang)}`
}
