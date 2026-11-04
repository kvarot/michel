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

/**
 * installDialogFocus starts the watcher, once for the page's life. It reads a
 * class that Vuetify sets, nothing else: what fails to find it does nothing.
 * @param {Document} doc
 */
export function installDialogFocus(doc) {
  const openDialog = '.v-dialog.v-overlay--active'
  let lastClicked = null
  let opener = null
  let wasOpen = false
  doc.addEventListener('click', (e) => {
    const el = e.target?.closest?.('button, a, [role="button"], input, [tabindex]')
    if (el && !el.closest('.v-overlay')) lastClicked = el
  }, true)
  new MutationObserver(() => {
    const open = !!doc.querySelector(openDialog)
    if (open === wasOpen) return
    wasOpen = open
    if (open) {
      opener = lastClicked
      return
    }
    const active = doc.activeElement
    const go = focusAfterDialog({ active, body: doc.body, inClosedDialog: !!active?.closest?.('.v-overlay'), opener })
    if (go === 'opener') opener.focus({ preventScroll: true })
    else if (go === 'main') doc.getElementById('main')?.focus({ preventScroll: true })
  }).observe(doc.body, { subtree: true, childList: true, attributes: true, attributeFilter: ['class'] })
}
