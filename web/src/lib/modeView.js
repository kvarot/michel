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
  return String(text).replace(idPattern, '').replace(/\s+([,.;:])/g, '$1').replace(/\s{2,}/g, ' ').trim()
}
