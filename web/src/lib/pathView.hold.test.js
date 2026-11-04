import { describe, expect, test } from 'vitest'
import { canDecide, groupOf, isFinal, stateLine } from './fixView.js'
import { canRestart, failurePath, holdView, showsPlan } from './pathView.js'
import { buildTodo, toneOf, todoWords } from './todoView.js'
import { translate } from '../i18n/index.js'
import { findJargon } from '../i18n/jargon.js'
import en from '../i18n/en.json'
import fr from '../i18n/fr.json'

// As GET /fix/{id} answers a held attempt (internal/api/fix.go, HoldView).
const hold = { count: 2, files: [{ file: 'src/config.php', lines: [2, 9] }], more: 0, hash: 'abc' }
const held = (extra = {}) => ({
  id: 'a1', state: 'held', project: 'demo', cause: '', branch: '', approved_by: '', proposal: null, messages: null,
  finding: { id: 'f1', package: 'acme/lib', status: 'pending' }, hold, ...extra,
})

describe('the path of a held attempt', () => {
  test('it waits in words, on the step before the proposal', () => {
    const p = failurePath({ attempt: held() })
    expect(p.note).toEqual({ key: 'held', params: { n: 2 } })
    expect(p.open).toBe(true)
    expect(p.steps.map((s) => s.state)).toEqual(['done', 'now', 'todo', 'todo', 'todo'])
    expect(p.steps[1].label).toBe('held')
    expect(translate('fr', `path.step.${p.steps[1].label}`)).toBe('Attend ta réponse')
  })
  test('a held attempt offers no start and no plan: the question stands instead', () => {
    expect(canRestart(held())).toBe(false)
    expect(showsPlan(held())).toBe(false)
    expect(canDecide(held())).toBe(false)
    expect(isFinal('held')).toBe(false)
    expect(groupOf('held')).toBe('review')
  })
  test('a flaw that left keeps the question, not the yes', () => {
    expect(failurePath({ attempt: held(), vanished: true }).note.key).toBe('held')
    expect(holdView(held(), true).canContinue).toBe(false)
    expect(holdView(held(), false).canContinue).toBe(true)
  })
  test('after a no, nothing runs and the fix can start again', () => {
    const a = held({ state: 'withdrawn', hold: undefined })
    const p = failurePath({ attempt: a })
    expect(p.note).toEqual({ key: 'withdrawn' })
    expect(p.steps.map((s) => s.state)).toEqual(['done', 'todo', 'todo', 'todo', 'todo'])
    expect(canRestart(a)).toBe(true)
    expect(canRestart(a, true)).toBe(false)
    expect(showsPlan(a)).toBe(true)
    expect(canDecide(a)).toBe(true)
    expect(isFinal('withdrawn')).toBe(true)
    expect(groupOf('withdrawn')).toBe('todo')
  })
})

describe('holdView', () => {
  test('only for a held attempt with its list', () => {
    expect(holdView(null)).toBeNull()
    expect(holdView(held({ state: 'preparing' }))).toBeNull()
    expect(holdView(held({ hold: undefined }))).toBeNull()
  })
  test('says the lines, one or several, and holds nothing but what the API gave', () => {
    const v = holdView(held({ hold: { count: 3, files: [{ file: 'a.php', lines: [1] }, { file: 'b.php', lines: [2, 9] }], more: 4, hash: 'h' } }))
    expect(v.count).toBe(3)
    expect(v.more).toBe(4)
    expect(v.hash).toBe('h')
    expect(v.files).toEqual([
      { file: 'a.php', linesKey: 'path.hold.line', lines: '1' },
      { file: 'b.php', linesKey: 'path.hold.lines', lines: '2, 9' },
    ])
  })
})

describe('the line in À faire', () => {
  const build = (attempts, lang = 'fr') => buildTodo({
    digest: { projects: [{ name: 'demo' }] }, servers: [], details: {}, attempts, findings: {}, lang, advanced: false, now: new Date('2026-11-03T12:00:00Z'),
  })
  test('rank À toi, with the number and a way to answer', () => {
    const r = build([held()])
    expect(r.lines).toHaveLength(1)
    const l = r.lines[0]
    expect(l.word).toBe('À toi')
    expect(l.tone).toBe('info')
    expect(l.rank).toBe(2)
    expect(l.title).toContain('2 clés')
    expect(l.action.label).toBe('Répondre')
    expect(l.action.href).toBe('#/fix/a1')
    expect(build([held()], 'en').lines[0].word).toBe('Yours')
  })
  test('a no asks nothing more of a list', () => {
    expect(build([held({ state: 'withdrawn', hold: undefined })]).lines).toHaveLength(0)
  })
  test('the word has its tone', () => {
    expect(todoWords).toContain('yours')
    expect(toneOf('yours')).toBe('info')
  })
})

describe('the words of a hold', () => {
  const keys = ['path.step.held', 'path.note.held.one', 'path.note.held.other', 'path.note.withdrawn', 'path.hold.title.one', 'path.hold.title.other',
    'path.hold.stopped', 'path.hold.check', 'path.hold.line', 'path.hold.lines', 'path.hold.more.one', 'path.hold.more.other', 'path.hold.if_continue.one', 'path.hold.if_continue.other',
    'path.hold.how.one', 'path.hold.how.other', 'path.hold.once', 'path.hold.gone', 'path.hold.withdraw', 'path.hold.continue',
    'todo.word.yours', 'todo.held.one', 'todo.held.other', 'todo.action.answer', 'fix.line.held', 'fix.line.withdrawn', 'fix.done.withdrawn', 'fix.chat.not_started']
  test('both languages have them', () => {
    for (const k of keys) {
      expect(fr[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
    }
  })
  test('the two choices are the ones asked', () => {
    expect(fr['path.hold.withdraw']).toBe("Je les retire d'abord")
    expect(fr['path.hold.continue']).toBe('Continuer quand même')
  })
  test('going on says the agent reads them and where they go', () => {
    expect(fr['path.hold.if_continue.other']).toContain('peut les lire')
    expect(fr['path.hold.if_continue.other']).toContain('Anthropic')
    expect(en['path.hold.if_continue.other']).toContain('can read them')
    expect(en['path.hold.if_continue.other']).toContain('Anthropic')
  })
  test('a plan no longer leaves the key without a word, and no text says the warning follows', () => {
    expect(fr['plan.project.keys']).toContain("l'agent ne démarre pas")
    expect(en['plan.project.keys']).toContain('the agent does not start')
    expect(fr['plan.project.self_start']).toContain('attend ta réponse')
    expect(en['plan.project.self_start']).toContain('waits for your answer')
  })
  test('one more file and several more files read right', () => {
    expect(translate('fr', 'path.hold.more', { n: 1, more: 1 })).toBe('Et dans 1 autre fichier.')
    expect(translate('fr', 'path.hold.more', { n: 3, more: 3 })).toBe('Et dans 3 autres fichiers.')
    expect(translate('en', 'path.hold.more', { n: 1, more: 1 })).toBe('And in 1 other file.')
    expect(translate('en', 'path.hold.more', { n: 3, more: 3 })).toBe('And in 3 other files.')
  })
  test('the page says the shape decides, and that a real key may not stop the agent', () => {
    expect(fr['plan.project.keys']).toContain('forme inhabituelle')
    expect(en['plan.project.keys']).toContain('unusual shape')
    expect(fr['path.hold.check']).toContain("Une vraie clé écrite d'une façon inhabituelle peut aussi passer sans que Michel s'arrête.")
    expect(en['path.hold.check']).toContain('A real key written in an unusual way can also get through without Michel stopping.')
    expect(fr['path.note.withdrawn']).toContain('Une fois les clés enlevées de ces fichiers')
    expect(en['path.note.withdrawn']).toContain('Once the keys are out of these files')
    expect(fr['plan.project.keys']).toContain("n'arrête pas l'agent")
    expect(en['plan.project.keys']).toContain('does not stop the agent')
  })
  test('the page says what an unanswered hold blocks, and how it ends', () => {
    expect(fr['path.hold.once']).toContain('aucune autre correction de ce projet')
    expect(fr['path.hold.once']).toContain('14 jours')
    expect(en['path.hold.once']).toContain('no other fix of this project')
    expect(en['path.hold.once']).toContain('14 days')
  })
  test('the end of a hold does not say the person chose: nobody may have answered', () => {
    for (const k of ['path.note.withdrawn', 'fix.line.withdrawn']) {
      expect(fr[k], k).not.toContain('Tu as choisi')
      expect(en[k], k).not.toContain('You chose')
    }
  })
  test('no jargon', () => {
    for (const k of keys.filter((x) => /^(path|todo)\./.test(x))) expect(findJargon(fr[k]), k).toEqual([])
  })
})

test('stateLine says a held attempt waits, and a no', () => {
  expect(stateLine({ kind: 'attempt', attempt: { state: 'held' } }, 'fr')).toBe(fr['fix.line.held'])
  expect(stateLine({ kind: 'attempt', attempt: { state: 'withdrawn' } }, 'en')).toBe(en['fix.line.withdrawn'])
})
