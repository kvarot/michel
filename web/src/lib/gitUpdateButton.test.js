import { readFileSync } from 'node:fs'
import { describe, expect, test } from 'vitest'
import fr from '../i18n/fr.json'
import en from '../i18n/en.json'

// B3: « Mettre à jour mon dossier » showed a plain blue bar, with no word, while it ran:
// the tonal variant it switched to kept the solid fill, so its text (the same blue) and its
// spinner vanished, and the person saw nothing. The component has no test harness, so the
// source is read: the button keeps one look, and what runs is said in words on the page.
const source = readFileSync(new URL('../components/GitUpdateButton.vue', import.meta.url), 'utf8')

describe('GitUpdateButton while it runs', () => {
  test('the button keeps the same variant: no tonal swap that hides its label', () => {
    expect(source).not.toMatch(/:variant=/)
    expect(source).not.toMatch(/tonal/)
  })
  test('the status is shown, not only read aloud', () => {
    expect(source).not.toMatch(/m-gitup__hidden/)
    expect(source).toMatch(/v-if="running"[^>]*class="m-gitup__wait/)
  })
  test('the wait sentence says it can take a moment and to wait here', () => {
    for (const cat of [fr, en]) expect(cat['git.update.wait']).toBeTruthy()
    expect(fr['git.update.wait']).toContain('attends ici')
  })
})

describe('MergeStep while it sends', () => {
  const merge = readFileSync(new URL('../components/MergeStep.vue', import.meta.url), 'utf8')
  test('the send button does not swap to tonal while it runs', () => {
    expect(merge).not.toMatch(/pushing \|\| step\.push\.pushed \? 'tonal'/)
  })
})
