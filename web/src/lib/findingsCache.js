// A small memory of what the overview and the Findings page read: the
// findings of each project and the digests sent, by language. A project's
// list is kept with the stamp of its last check (its last scan time and its
// count), so a new check makes Michel read it again by itself; a decision or
// a change on another page, or « Actualiser », clears everything. Plain
// objects, no DOM, no fetch, no storage. Vitest covers it (findingsCache.test.js).

/** stampOf is what must not have changed for a project's list to be reused. */
export function stampOf(project) {
  return `${project?.last_scan_at || ''}|${project?.total ?? ''}|${project?.last_scan_status || ''}`
}

/**
 * createCache makes an empty memory.
 * @returns {{
 *   lists: (lang: string, projects: object[]|null) => Record<string, object[]>,
 *   keep: (lang: string, projects: object[]|null, lists: Record<string, object[]|null>) => void,
 *   runs: (lang: string) => object[]|null,
 *   keepRuns: (lang: string, runs: object[]|null) => void,
 *   clear: () => void,
 * }}
 */
export function createCache() {
  let byLang = {}
  let runsByLang = {}
  return {
    /** lists gives the lists still good for these projects: same language, same stamp. */
    lists(lang, projects) {
      const kept = byLang[lang] || {}
      const out = {}
      for (const p of Array.isArray(projects) ? projects : []) {
        const e = p && kept[p.name]
        if (e && e.stamp === stampOf(p)) out[p.name] = e.list
      }
      return out
    },
    /** keep remembers the lists read (a list not read is not kept). */
    keep(lang, projects, lists) {
      if (!Array.isArray(projects)) return
      const kept = { ...(byLang[lang] || {}) }
      for (const p of projects) {
        if (!p || !Array.isArray(lists?.[p.name])) continue
        kept[p.name] = { stamp: stampOf(p), list: lists[p.name] }
      }
      byLang[lang] = kept
    },
    /** runs gives the digests read in that language, null when none were kept. */
    runs(lang) {
      return Object.prototype.hasOwnProperty.call(runsByLang, lang) ? runsByLang[lang] : null
    },
    /** keepRuns remembers the digests read; null (not read) is not kept. */
    keepRuns(lang, runs) {
      if (Array.isArray(runs)) runsByLang = { ...runsByLang, [lang]: runs }
    },
    clear() {
      byLang = {}
      runsByLang = {}
    },
  }
}

/** findingsCache is the one memory the pages share. */
export const findingsCache = createCache()
