/**
 * findJargon lists the kinds of unexplained jargon a simple-mode text holds.
 * @param {string} text
 * @param {boolean} [allowed] true when the key may use port, paquet or SSH.
 * @returns {string[]}
 */
export function findJargon(text, allowed = false) {
  const found = []
  if (/\b(CVE|CVSS|GHSA|EPSS|KEV)\b/.test(text)) found.push('identifier word')
  if (!allowed && /\b(ports?|paquets?|SSH)\b/i.test(text)) found.push('port, paquet or SSH')
  if (!allowed && /\b(TCP|UDP|loopback|netstat)\b/.test(text)) found.push('network word')
  return found
}

/**
 * catalogJargon lists the jargon of a whole catalog, as "key: kind".
 * @param {Object<string, string>} catalog
 * @param {{exempt: string[], exceptions: string[]}} rules exempt holds family
 *   prefixes that only advanced mode shows, exceptions the keys allowed to use
 *   port, paquet or SSH because their sentence explains the word.
 * @returns {string[]}
 */
export function catalogJargon(catalog, { exempt, exceptions }) {
  const bad = []
  for (const [k, v] of Object.entries(catalog)) {
    if (exempt.some((f) => k.startsWith(f))) continue
    for (const why of findJargon(String(v), exceptions.includes(k))) bad.push(`${k}: ${why}`)
  }
  return bad
}
