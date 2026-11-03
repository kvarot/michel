/**
 * The guided interface palette. Every text color reaches AA (4.5:1) on the
 * backgrounds it is drawn on; theme.test.js checks it. A severity is still
 * a color and a word, never a color alone.
 */

/** @typedef {{dark: boolean, colors: Record<string, string>}} MichelTheme */

/** @type {{light: MichelTheme, dark: MichelTheme}} */
export const themes = {
  light: {
    dark: false,
    colors: {
      background: '#F4F7FA', surface: '#FFFFFF', 'surface-variant': '#E6EEF6',
      'on-background': '#14304F', 'on-surface': '#14304F', 'on-surface-variant': '#14304F',
      primary: '#1B62B5', info: '#1B62B5', low: '#1B62B5', 'on-primary': '#FFFFFF',
      secondary: '#566879', unknown: '#566879',
      success: '#0F6B52',
      warning: '#9A5B00', medium: '#9A5B00',
      error: '#B3261E', critical: '#B3261E',
      high: '#B4501A',
      nav: '#14304F', 'on-nav': '#FFFFFF', 'nav-active': '#264A70',
      line: '#D3DDE8',
      'tag-urgent': '#FBEAEA', 'tag-look': '#FDF2DE', 'tag-done': '#E3F4EE', 'tag-info': '#E6EEF6',
    },
  },
  dark: {
    dark: true,
    colors: {
      background: '#0F1C2B', surface: '#172737', 'surface-variant': '#22364A',
      'on-background': '#E6EEF6', 'on-surface': '#E6EEF6', 'on-surface-variant': '#E6EEF6',
      primary: '#8FBDF0', info: '#8FBDF0', low: '#8FBDF0', 'on-primary': '#0F1C2B',
      secondary: '#A9BCCC', unknown: '#A9BCCC',
      success: '#6FD3B5',
      warning: '#E9B860', medium: '#E9B860',
      error: '#FF9A90', critical: '#FF9A90',
      high: '#FFB074',
      nav: '#0A1521', 'on-nav': '#E6EEF6', 'nav-active': '#22364A',
      line: '#2E4459',
      'tag-urgent': '#333542', 'tag-look': '#30383C', 'tag-done': '#223C46', 'tag-info': '#293949',
    },
  },
}

/** @param {string} hex #RRGGBB @returns {number} relative luminance */
function luminance(hex) {
  const n = parseInt(hex.slice(1), 16)
  const lin = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => {
    const s = v / 255
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
  })
  return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]
}

/**
 * contrast returns the WCAG contrast ratio of two #RRGGBB colors (1 to 21).
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function contrast(a, b) {
  const la = luminance(a)
  const lb = luminance(b)
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
}
