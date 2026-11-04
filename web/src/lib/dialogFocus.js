// A dialog of this app is opened by code, so Vuetify has no activator to give
// the keyboard back to: closed by Escape, it would be left on the page itself.
// One watcher for the whole app brings it back to the button that opened it.

/**
 * focusAfterDialog decides where the keyboard goes when the last dialog closed.
 * A page that already placed it keeps it.
 * @param {{active: *, body: *, inClosedDialog: boolean, opener: {isConnected: boolean}|null}} input
 * @returns {'opener'|'main'|'keep'}
 */
export function focusAfterDialog({ active, body, inClosedDialog, opener }) {
  if (active && active !== body && !inClosedDialog) return 'keep'
  return opener?.isConnected ? 'opener' : 'main'
}

const openDialog = '.v-dialog.v-overlay--active'

/**
 * dialogWatcher is the state behind the watcher: the last button clicked, the
 * opener kept when a dialog opened, and whether one was open at the last look.
 * It needs of the document only what the tests can fake.
 * @param {Document} doc
 */
export function dialogWatcher(doc) {
  let lastClicked = null
  let opener = null
  let wasOpen = false
  return {
    click(e) {
      const el = e.target?.closest?.('button, a, [role="button"], input, [tabindex]')
      if (el && !el.closest('.v-overlay')) lastClicked = el
    },
    look() {
      const open = !!doc.querySelector(openDialog)
      if (open === wasOpen) return
      wasOpen = open
      if (open) {
        // A click opens one dialog at most: a dialog opened with no click goes to the main area.
        opener = lastClicked
        lastClicked = null
        return
      }
      const active = doc.activeElement
      const go = focusAfterDialog({ active, body: doc.body, inClosedDialog: !!active?.closest?.('.v-overlay'), opener })
      if (go === 'opener') {
        opener.focus({ preventScroll: true })
        // A disabled or hidden button takes no focus: the keyboard must not be left on nothing.
        if (doc.activeElement !== opener) doc.getElementById('main')?.focus({ preventScroll: true })
      } else if (go === 'main') doc.getElementById('main')?.focus({ preventScroll: true })
      opener = null
    },
  }
}

/**
 * installDialogFocus starts the watcher, once for the page's life. It reads a
 * class that Vuetify sets, nothing else: what fails to find it does nothing.
 * @param {Document} doc
 */
export function installDialogFocus(doc) {
  const w = dialogWatcher(doc)
  doc.addEventListener('click', (e) => w.click(e), true)
  new MutationObserver(() => w.look()).observe(doc.body, { subtree: true, childList: true, attributes: true, attributeFilter: ['class'] })
}
