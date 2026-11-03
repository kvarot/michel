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
