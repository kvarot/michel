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

/** escaped makes a text literal in a regular expression. */
function escaped(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

const exampleClause = /,\s*(?:par exemple|for example)\s+\S+:\d+(?=[.\s]|$)/gi

/**
 * plainSentence is a sentence of Michel for the simple mode: no file of the
 * person's code ("par exemple src/Foo.php:12"), no rule or advisory name, no
 * CVE or GHSA id. The advanced mode shows the sentence as it is.
 * @param {string | undefined} text
 * @param {object | null} [facts] the finding: analysis, location, rule_id, osv_id
 * @returns {string}
 */
export function plainSentence(text, facts) {
  let s = String(text || '')
  if (!s) return ''
  const site = facts?.analysis?.calls?.sites?.[0]
  for (const place of [site && `${site.file}:${site.line}`, facts?.location]) {
    if (place) s = s.replace(new RegExp(`(?:,\\s*(?:par exemple|for example)|\\s(?:dans|in))\\s+${escaped(place)}`, 'gi'), '')
  }
  s = s.replace(exampleClause, '')
  for (const id of [facts?.rule_id, facts?.osv_id]) {
    if (id) s = s.replace(new RegExp(`\\s*\\(?(?<![\\w.-])${escaped(id)}(?![\\w-])\\)?`, 'g'), '')
  }
  return stripTechnicalIds(s).trim()
}
