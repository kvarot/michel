// How many of a package's flaw sheets a row unfolds at first (B9): a package can carry a dozen
// advisories, and one card must not become a page. The rest stays one click away.
const firstFew = 3

/**
 * visibleSheets cuts a row's finding ids: the first few, then « et N autres » until asked.
 * The ids come worst first (urgent, then by severity), and a flaw urgent or critical is
 * never folded: mustShow of them stay open, however many.
 * @param {string[]} ids
 * @param {boolean} all the person asked for the others
 * @param {number} [mustShow] how many of the first ids are urgent or critical
 * @returns {{shown: string[], hidden: number}}
 */
export function visibleSheets(ids, all, mustShow = 0) {
  const list = Array.isArray(ids) ? ids : []
  const limit = Math.max(firstFew, mustShow)
  if (all || list.length <= limit) return { shown: list, hidden: 0 }
  return { shown: list.slice(0, limit), hidden: list.length - limit }
}
