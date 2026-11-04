import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, test } from 'vitest'
import { dialogWatcher, focusAfterDialog } from './dialogFocus.js'

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

// A document as the watcher reads it: whether a dialog is open, where the keyboard is, who takes focus.
function fakeDoc() {
  const doc = {
    body: { name: 'body' },
    dialogOpen: false,
    activeElement: null,
    focused: [],
    querySelector: () => (doc.dialogOpen ? {} : null),
    getElementById: (id) => (id === 'main' ? { focus: () => { doc.focused.push('main'); doc.activeElement = { name: 'main' } } } : null),
  }
  doc.activeElement = doc.body
  return doc
}
const button = (doc, name, { takesFocus = true } = {}) => ({
  name,
  isConnected: true,
  closest: () => null,
  focus() {
    doc.focused.push(name)
    if (takesFocus) doc.activeElement = this
  },
})
const clickOn = (w, el) => w.click({ target: { closest: () => el } })

describe('the watcher', () => {
  test('the keyboard returns to the button that opened the dialog', () => {
    const doc = fakeDoc()
    const w = dialogWatcher(doc)
    const opener = button(doc, 'open')
    clickOn(w, opener)
    doc.dialogOpen = true
    w.look()
    doc.dialogOpen = false
    w.look()
    expect(doc.focused).toEqual(['open'])
  })
  test('nothing moves while a dialog stays open, or when nothing changed', () => {
    const doc = fakeDoc()
    const w = dialogWatcher(doc)
    clickOn(w, button(doc, 'open'))
    doc.dialogOpen = true
    w.look()
    w.look()
    w.look()
    expect(doc.focused).toEqual([])
  })
  test('a page that already placed the keyboard keeps it', () => {
    const doc = fakeDoc()
    const w = dialogWatcher(doc)
    clickOn(w, button(doc, 'open'))
    doc.dialogOpen = true
    w.look()
    doc.activeElement = { name: 'page chose', closest: () => null }
    doc.dialogOpen = false
    w.look()
    expect(doc.focused).toEqual([])
  })
  test('the opener is not kept: a dialog opened with no click goes to the main area', () => {
    const doc = fakeDoc()
    const w = dialogWatcher(doc)
    clickOn(w, button(doc, 'old'))
    doc.dialogOpen = true
    w.look()
    doc.dialogOpen = false
    w.look()
    doc.activeElement = doc.body
    doc.dialogOpen = true
    w.look()
    doc.dialogOpen = false
    w.look()
    expect(doc.focused).toEqual(['old', 'main'])
  })
  test('an opener that takes no focus leaves the keyboard on the main area, not on nothing', () => {
    const doc = fakeDoc()
    const w = dialogWatcher(doc)
    clickOn(w, button(doc, 'disabled', { takesFocus: false }))
    doc.dialogOpen = true
    w.look()
    doc.dialogOpen = false
    w.look()
    expect(doc.focused).toEqual(['disabled', 'main'])
  })
  test('a click inside a dialog is not an opener', () => {
    const doc = fakeDoc()
    const w = dialogWatcher(doc)
    w.click({ target: { closest: (sel) => (sel === '.v-overlay' ? {} : { closest: () => ({}) }) } })
    doc.dialogOpen = true
    w.look()
    doc.dialogOpen = false
    w.look()
    expect(doc.focused).toEqual(['main'])
  })
})

describe('Vuetify still names what the watcher reads', () => {
  const root = fileURLToPath(new URL('../../node_modules/vuetify/lib/components/', import.meta.url))
  test('the open overlay and the dialog class', () => {
    expect(readFileSync(`${root}VOverlay/VOverlay.js`, 'utf8')).toContain('v-overlay--active')
    expect(readFileSync(`${root}VDialog/VDialog.js`, 'utf8')).toContain('v-dialog')
  })
})
