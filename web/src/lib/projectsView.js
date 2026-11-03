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
 * @param {{scanning?: boolean, last_failure?: object|null, last_scan_status?: string}} project
 * @returns {boolean}
 */
export function checkedWell(project) {
  return !project.scanning && !project.last_failure && project.last_scan_status === 'ok'
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
  if (project.scanning || project.last_scan_status === 'running') return t('project.scan.running')
  if (showsFailure(project)) return project.last_failure.error
  switch (project.last_scan_status) {
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

/** @param {{scanning?: boolean}[]|null} views @returns {boolean} a check is running somewhere. */
export function anyScanning(views) {
  return (views || []).some((v) => v.scanning)
}

/** @param {string} name @param {string} lang @returns {string} the API path that starts the check of a project. */
export function scanPath(name, lang) {
  return `/projects/${encodeURIComponent(name)}/scan?lang=${encodeURIComponent(lang)}`
}
