// localStorage can be missing or throw (private window, blocked site data):
// every access goes through these two functions, and the page works without.

/** @param {string} key @returns {string} the stored value, or "". */
export function load(key) {
  try {
    return window.localStorage.getItem(key) || ''
  } catch {
    return ''
  }
}

/** save stores value under key; an empty value removes it. Failures are ignored. */
export function save(key, value) {
  try {
    if (value) window.localStorage.setItem(key, value)
    else window.localStorage.removeItem(key)
  } catch {
    // Nothing to do: the setting lasts until the page is closed.
  }
}

export const keys = { token: 'michel.token', lang: 'michel.lang', theme: 'michel.theme' }
