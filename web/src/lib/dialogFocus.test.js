import { describe, expect, test } from 'vitest'
import { focusAfterDialog } from './dialogFocus.js'

const body = { name: 'body' }
const opener = { isConnected: true }

describe('where the keyboard goes when a dialog closes', () => {
  test('back to the button that opened it, when it was left on nothing', () => {
    expect(focusAfterDialog({ active: body, body, inClosedDialog: false, opener })).toBe('opener')
    expect(focusAfterDialog({ active: null, body, inClosedDialog: false, opener })).toBe('opener')
  })
  test('back to it from inside the dialog that is fading out', () => {
    expect(focusAfterDialog({ active: { name: 'x' }, body, inClosedDialog: true, opener })).toBe('opener')
  })
  test('a page that already moved the keyboard keeps it', () => {
    expect(focusAfterDialog({ active: { name: 'x' }, body, inClosedDialog: false, opener })).toBe('keep')
  })
  test('a button that is gone gives the main area', () => {
    expect(focusAfterDialog({ active: body, body, inClosedDialog: false, opener: { isConnected: false } })).toBe('main')
    expect(focusAfterDialog({ active: body, body, inClosedDialog: false, opener: null })).toBe('main')
  })
})
