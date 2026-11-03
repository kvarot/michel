import { describe, it, expect } from 'vitest'
import { themes, contrast } from './theme.js'

const textOnBackgrounds = [
  'on-background', 'primary', 'success', 'warning', 'error', 'critical',
  'high', 'medium', 'low', 'unknown', 'secondary',
]
const pairs = [
  ['on-primary', 'primary'],
  ['on-nav', 'nav'],
  ['on-nav', 'nav-active'],
  ['error', 'tag-urgent'],
  ['warning', 'tag-look'],
  ['success', 'tag-done'],
  ['secondary', 'tag-info'],
]

describe('contrast', () => {
  it('is 21 for black on white and 1 for the same color', () => {
    expect(contrast('#000000', '#FFFFFF')).toBeCloseTo(21, 1)
    expect(contrast('#14304F', '#14304F')).toBeCloseTo(1, 5)
  })
})

describe.each(['light', 'dark'])('%s theme', (name) => {
  const c = themes[name].colors
  it('every text color reaches AA on its backgrounds', () => {
    const low = []
    for (const fg of textOnBackgrounds) {
      for (const bg of ['background', 'surface']) {
        if (contrast(c[fg], c[bg]) < 4.5) low.push(`${fg} on ${bg}`)
      }
    }
    for (const [fg, bg] of pairs) {
      if (contrast(c[fg], c[bg]) < 4.5) low.push(`${fg} on ${bg}`)
    }
    expect(low).toEqual([])
  })
  it('declares the dark flag', () => {
    expect(themes[name].dark).toBe(name === 'dark')
  })
})
