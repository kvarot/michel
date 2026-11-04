// Pure choices behind the AI consent dialog (B5). The simple mode opens with one plain
// paragraph that is true for the kind of target the consent is for: a project (files of a
// copy of the code go out) or a server (its versions and settings go out, the agent never
// connects to it, and a health server sends nothing). The lines the server provides are the
// consent itself (what leaves, to whom, the sensitive classification, each extra host): they
// are never folded away. Only Michel's technical wording about the protection setting
// (strict_local, the policy file, the backup) sits behind « Voir le détail », open in the
// advanced mode.

/** serverHealthLine is the line a health server's consent holds instead of the others. */
const serverHealthLine = 'fix.consent.server_health'

/**
 * consentView says what the dialog shows.
 * @param {{kind?: 'project'|'server', switchMode: boolean, advanced: boolean, lines?: {what: string}[]}} args
 *   kind: whose consent it is (default project). switchMode: the policy is strict_local.
 *   lines: the consent lines of the server, read to tell a health server.
 * @returns {{plain: string[], detailOpen: boolean, detailButton: boolean, accept: string}}
 *   plain: catalog keys of the paragraphs of the simple mode, in order
 */
export function consentView({ kind = 'project', switchMode, advanced, lines = [] }) {
  const health = kind === 'server' && lines.some((l) => l.what === serverHealthLine)
  let plain = []
  if (!advanced) {
    if (health) plain = ['fix.consent.plain_server_health']
    else plain = [kind === 'server' ? 'fix.consent.plain_server' : 'fix.consent.plain_project', ...(switchMode ? ['fix.consent.plain_switch'] : [])]
  }
  return {
    plain,
    detailOpen: advanced,
    detailButton: !advanced && switchMode,
    accept: advanced ? (switchMode ? 'fix.consent.strict_accept' : 'fix.consent.accept') : switchMode ? 'fix.consent.accept_plain_switch' : 'fix.consent.accept_plain',
  }
}
