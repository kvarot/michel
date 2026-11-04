// Pure choices behind the AI consent dialog (B5). The simple mode opens with one plain
// paragraph that is true for the kind of target the consent is for: a project (files of a
// copy of the code go out) or a server (its versions and settings go out, the agent never
// connects to it). The lines the server provides are the consent itself (what leaves, to
// whom, the sensitive classification, each extra host): they are never folded away. Under
// strict_local the plain paragraph says the guarantee lost, the frame kept and that it holds
// for all of Michel; only the technical names (strict_local, .bak) sit behind « Voir le
// détail ». A health server never reaches this dialog: the API refuses its consent.

/**
 * consentView says what the dialog shows.
 * @param {{kind?: 'project'|'server', switchMode: boolean, advanced: boolean}} args
 *   kind: whose consent it is (default project). switchMode: the policy is strict_local.
 * @returns {{plain: string[], detailOpen: boolean, detailButton: boolean, accept: string}}
 *   plain: catalog keys of the paragraphs of the simple mode, in order
 */
export function consentView({ kind = 'project', switchMode, advanced }) {
  let plain = []
  if (!advanced) plain = [kind === 'server' ? 'fix.consent.plain_server' : 'fix.consent.plain_project', ...(switchMode ? ['fix.consent.plain_switch'] : [])]
  return {
    plain,
    detailOpen: advanced,
    detailButton: !advanced && switchMode,
    accept: advanced ? (switchMode ? 'fix.consent.strict_accept' : 'fix.consent.accept') : switchMode ? 'fix.consent.accept_plain_switch' : 'fix.consent.accept_plain',
  }
}
