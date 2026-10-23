// Interface text of the page. Generated text (the digest's title, Michel's
// word, the three sentences) comes already translated from the API; every
// other string the page shows lives in fr.json and en.json.
import en from './en.json'
import fr from './fr.json'

export const catalogs = { en, fr }
export const languages = ['fr', 'en']

/** @param {string} lang @returns {'fr'|'en'} a supported language, English otherwise. */
export function normalizeLang(lang) {
  const l = String(lang || '').toLowerCase()
  return l === 'fr' || l === 'en' ? l : 'en'
}

/**
 * pluralKey picks key.one or key.other for n. French treats 0 and 1 as
 * singular, English only 1.
 */
function pluralKey(lang, n) {
  if (lang === 'fr') return n <= 1 ? 'one' : 'other'
  return n === 1 ? 'one' : 'other'
}

/**
 * translate returns the text of key in lang with {name} replaced by
 * params.name. When params.n is a number and key.one / key.other exist, the
 * plural form is chosen. A missing key falls back to English, then to the key.
 * @param {string} lang @param {string} key @param {Record<string, any>} [params]
 */
export function translate(lang, key, params = {}) {
  const l = normalizeLang(lang)
  let k = key
  if (typeof params.n === 'number' && (catalogs[l][`${key}.one`] !== undefined || catalogs.en[`${key}.one`] !== undefined)) {
    k = `${key}.${pluralKey(l, params.n)}`
  }
  const text = catalogs[l][k] ?? catalogs.en[k] ?? key
  return text.replace(/\{(\w+)\}/g, (m, name) => (params[name] === undefined ? m : String(params[name])))
}
