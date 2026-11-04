import { describe, it, expect } from 'vitest'
import { themes, contrast } from './theme.js'
import { toneOf, todoWords } from './todoView.js'

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
  it('every word of the to-do list, « important » (high) included, is drawn in a tone that reaches AA on its tag fill', () => {
    // styles.css: .m-tag--urgent, --look and --info draw these colors on these fills.
    const drawn = { urgent: ['error', 'tag-urgent'], look: ['warning', 'tag-look'], info: ['secondary', 'tag-info'] }
    const low = []
    for (const word of todoWords) {
      const pair = drawn[toneOf(word)]
      if (!pair) low.push(`${word}: no tag for its tone`)
      else if (contrast(c[pair[0]], c[pair[1]]) < 4.5) low.push(`${word} on ${pair[1]}`)
    }
    expect(todoWords).toContain('important')
    expect(toneOf('important')).toBe('look')
    expect(low).toEqual([])
  })
  it('declares the dark flag', () => {
    expect(themes[name].dark).toBe(name === 'dark')
  })
})
