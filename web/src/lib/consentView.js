// Pure choices behind the AI consent dialog (B5). The simple mode opens with one plain
// paragraph (what goes out, to whom, what changes); the full text of the consent, the
// technical lines the server wrote, stays one click away under « Voir le détail », and is
// open from the start in the advanced mode. Nothing a consent needs is left out of the plain
// paragraph: the company, that code goes out, that the secrets Michel knows are masked.

/**
 * consentView says what the dialog shows.
 * @param {{switchMode: boolean, advanced: boolean}} args switchMode: the policy is strict_local
 * @returns {{plain: string[], detailOpen: boolean, detailButton: boolean, accept: string}}
 *   plain: catalog keys of the paragraphs of the simple mode, in order
 */
export function consentView({ switchMode, advanced }) {
  return {
    plain: advanced ? [] : switchMode ? ['fix.consent.plain', 'fix.consent.plain_switch'] : ['fix.consent.plain'],
    detailOpen: advanced,
    detailButton: !advanced,
    accept: advanced ? (switchMode ? 'fix.consent.strict_accept' : 'fix.consent.accept') : switchMode ? 'fix.consent.accept_plain_switch' : 'fix.consent.accept_plain',
  }
}
