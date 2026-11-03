import { keys } from './storage.js'

/**
 * readAdvanced says whether the advanced mode is on. Only the stored value "1"
 * turns it on; an empty, unknown or unreadable value leaves the simple mode.
 * @param {(key: string) => string} load reads a stored value (storage.js load).
 * @returns {boolean}
 */
export function readAdvanced(load) {
  try {
    return load(keys.advanced) === '1'
  } catch {
    return false
  }
}

const idPattern = /\s*\(?\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[a-z0-9]{4}){3})\b\)?/gi

/**
 * stripTechnicalIds removes CVE and GHSA identifiers from a sentence and keeps
 * the rest. Names such as PHP2Shell stay.
 * @param {string | undefined} text
 * @returns {string}
 */
export function stripTechnicalIds(text) {
  if (!text) return ''
  const s = String(text)
  const stripped = s.replace(idPattern, '')
  if (stripped === s) return s
  const startsWithId = /^\s*\(?(?:CVE-|GHSA-)/i.test(s)
  const endsWithId = /(?:CVE-\d{4}-\d{4,}|GHSA(?:-[a-z0-9]{4}){3})\)?[\s.!?]*$/i.test(s)
  let out = stripped.replace(/\s+([,.;:])/g, '$1').replace(/\s{2,}/g, ' ').trim()
  // What an id leaves behind: a dangling "et"/"and" or comma, only at an end
  // where an id was. "Et voilà" keeps its "Et".
  if (startsWithId) {
    out = out.replace(/^(?:(?:et|and)\s+|[,;:]\s*)+/i, '')
    out = out.charAt(0).toUpperCase() + out.slice(1)
  }
  if (endsWithId) {
    out = out.replace(/\s*[,;:]?\s*\b(?:et|and)\s*$/i, '')
    out = out.replace(/[,;:]+(?=[.!?]?$)/, '').trim()
  }
  return out
}
