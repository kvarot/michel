// Pure functions behind the path of a flaw. For now only the one fact the
// Resolved page needs: whether a fix is verified. No DOM, no fetch.

/**
 * isVerified says whether a fix attempt counts as « Vérifiée » (ruling R2).
 * A project's fix needs the proof (state proven_fixed) and a clean new scan of
 * the copy (proposal.rescan_clean): rescan_clean alone is known from the
 * proposal on, before any agreement, so it never lights the step by itself.
 * A server's fix needs the proof only: Michel sets it after a full reading that
 * no longer sees the flaw. inconclusive is never verified. In both cases the
 * flaw must still be gone (finding.status): a proven_fixed attempt never leaves
 * its final state, so a flaw that came back would otherwise stay « Vérifiée ».
 * @param {object|null|undefined} attempt an element of GET /fixes
 * @returns {boolean}
 */
export function isVerified(attempt) {
  if (!attempt || attempt.state !== 'proven_fixed') return false
  if (attempt.finding?.status !== 'gone') return false
  if (attempt.server) return true
  return attempt.proposal?.rescan_clean === true
}
