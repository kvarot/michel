// How many of a package's flaw sheets a row unfolds at first (B9): a package can carry a dozen
// advisories, and one card must not become a page. The rest stays one click away.
const firstFew = 3

/**
 * visibleSheets cuts a row's finding ids: the first few, then « et N autres » until asked.
 * @param {string[]} ids
 * @param {boolean} all the person asked for the others
 * @returns {{shown: string[], hidden: number}}
 */
export function visibleSheets(ids, all) {
  const list = Array.isArray(ids) ? ids : []
  if (all || list.length <= firstFew) return { shown: list, hidden: 0 }
  return { shown: list.slice(0, firstFew), hidden: list.length - firstFew }
}
