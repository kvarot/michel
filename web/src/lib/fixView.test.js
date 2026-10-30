import { describe, expect, test } from 'vitest'
import {
  acceptResult, activityLine, canApprove, fixGroups, fixHash, fixRoute, selectAction, groupAttempts, isFinal, levelLabel, levels, mergeMessages,
  proposalFacts, proposalSentence, splitMasked, stateLine,
} from './fixView.js'

/** attempt builds an AttemptView as GET /fixes answers it. */
function attempt(id, state, findingId, extra = {}) {
  return {
    id, state, project: 'demo', cause: '', branch: '', proposal: null, messages: null,
    finding: { id: findingId, package: 'acme/lib', osv_id: `GHSA-${findingId}`, severity: 'high', installed_version: '1.0.0', fixed_versions: ['1.0.5'], status: 'pending' },
    ...extra,
  }
}

describe('groupAttempts', () => {
  test('puts every attempt in one of the four groups, in order', () => {
    const groups = groupAttempts([
      attempt('a1', 'preparing', 'f1'),
      attempt('a2', 'proposed', 'f2'),
      attempt('a3', 'applied', 'f3'),
      attempt('a4', 'failed', 'f4'),
      attempt('a5', 'approved', 'f5'),
      attempt('a6', 'proven_fixed', 'f6'),
      attempt('a7', 'refused', 'f7'),
      attempt('a8', 'inconclusive', 'f8'),
    ])
    expect(groups.map((g) => g.key)).toEqual(fixGroups)
    expect(fixGroups).toEqual(['todo', 'running', 'review', 'done'])
    const ids = (k) => groups.find((g) => g.key === k).items.map((i) => i.attempt.id)
    expect(ids('todo')).toEqual(['a4', 'a7'])
    expect(ids('running')).toEqual(['a1', 'a5'])
    expect(ids('review')).toEqual(['a2'])
    expect(ids('done')).toEqual(['a3', 'a6', 'a8'])
  })

  test('keeps one line per finding: its newest attempt', () => {
    const groups = groupAttempts([attempt('new', 'proposed', 'f1'), attempt('old', 'refused', 'f1')])
    expect(groups[0].items).toEqual([])
    expect(groups[2].items.map((i) => i.attempt.id)).toEqual(['new'])
  })

  test('adds the open findings without an attempt to "todo"', () => {
    const groups = groupAttempts([attempt('a1', 'preparing', 'f1'), attempt('a2', 'failed', 'f2')], [
      { id: 'f1', package: 'acme/lib', project: 'demo' },
      { id: 'f2', package: 'acme/lib', project: 'demo' },
      { id: 'f3', package: 'vuln-pkg', project: 'demo' },
    ])
    const todo = groups[0].items
    expect(todo.map((i) => [i.kind, i.kind === 'attempt' ? i.attempt.id : i.finding.id])).toEqual([['attempt', 'a2'], ['finding', 'f3']])
    expect(todo.map((i) => i.findingId)).toEqual(['f2', 'f3'])
  })

  test('drops a failed attempt whose finding is gone, and copes with nothing', () => {
    const gone = attempt('a1', 'failed', 'f1')
    gone.finding.status = 'gone'
    expect(groupAttempts([gone])[0].items).toEqual([])
    expect(groupAttempts(null).map((g) => g.items.length)).toEqual([0, 0, 0, 0])
  })
})

describe('proposalSentence', () => {
  const facts = { package: 'guzzlehttp/guzzle', from: '7.4.0', to: '7.4.5', sites: 12, tests: 'passed' }

  test('says the versions, the call sites and the tests in French', () => {
    expect(proposalSentence(facts, 'fr')).toBe("Je passe guzzlehttp/guzzle de 7.4.0 à 7.4.5 ; 12 endroits de ton code l'utilisent, les tests passent.")
    expect(proposalSentence({ ...facts, sites: 1, tests: 'failed' }, 'fr')).toBe("Je passe guzzlehttp/guzzle de 7.4.0 à 7.4.5 ; 1 endroit de ton code l'utilise, les tests échouent.")
    expect(proposalSentence({ ...facts, sites: 0, tests: 'not_run' }, 'fr')).toBe("Je passe guzzlehttp/guzzle de 7.4.0 à 7.4.5 ; ton code ne s'en sert pas directement, les tests n'ont pas pu être lancés.")
  })

  test('says it in English', () => {
    expect(proposalSentence(facts, 'en')).toBe('I move guzzlehttp/guzzle from 7.4.0 to 7.4.5; 12 places in your code use it, the tests pass.')
    expect(proposalSentence({ ...facts, sites: 1 }, 'en')).toBe('I move guzzlehttp/guzzle from 7.4.0 to 7.4.5; 1 place in your code uses it, the tests pass.')
  })

  test('leaves out what is unknown', () => {
    expect(proposalSentence({ ...facts, sites: null }, 'fr')).toBe('Je passe guzzlehttp/guzzle de 7.4.0 à 7.4.5 ; les tests passent.')
    expect(proposalSentence({ ...facts, to: '' }, 'en')).toBe('I update guzzlehttp/guzzle (installed: 7.4.0); 12 places in your code use it, the tests pass.')
    expect(proposalSentence(null, 'fr')).toBe('')
  })

  test('proposalFacts reads the attempt and the finding sheet', () => {
    const a = attempt('a1', 'proposed', 'f1', { proposal: { tests_status: 'passed', hash: 'h' } })
    const sheet = { analysis: { upgrade: { target: '1.0.3' }, calls: { count: 4 } } }
    expect(proposalFacts(a, sheet)).toEqual({ package: 'acme/lib', from: '1.0.0', to: '1.0.3', sites: 4, tests: 'passed' })
    expect(proposalFacts(a, null)).toEqual({ package: 'acme/lib', from: '1.0.0', to: '1.0.5', sites: null, tests: 'passed' })
    // The proposal's own versions (what the fix commit resolves) come first.
    a.proposal = { tests_status: 'failed', hash: 'h', from_version: '0.9.9', to_version: '1.0.7' }
    expect(proposalFacts(a, sheet)).toEqual({ package: 'acme/lib', from: '0.9.9', to: '1.0.7', sites: 4, tests: 'failed' })
  })
})

describe('canApprove', () => {
  test('only a proposed attempt with a proposal', () => {
    const p = { hash: 'abc' }
    expect(canApprove({ state: 'proposed', proposal: p })).toBe(true)
    for (const s of ['preparing', 'approved', 'refused', 'applied', 'proven_fixed', 'inconclusive', 'failed', 'superseded']) {
      expect(canApprove({ state: s, proposal: p })).toBe(false)
    }
    expect(canApprove({ state: 'proposed', proposal: null })).toBe(false)
    expect(canApprove(null)).toBe(false)
  })

  test('isFinal: the stream stops on these states', () => {
    expect(['refused', 'applied', 'proven_fixed', 'inconclusive', 'failed', 'superseded'].every(isFinal)).toBe(true)
    expect(['preparing', 'proposed', 'approved'].some(isFinal)).toBe(false)
  })
})

describe('levelLabel', () => {
  test('names the four levels in sentences', () => {
    expect(levels).toEqual([0, 1, 2, 3])
    expect(levelLabel(0, 'fr').title).toBe('Signaler')
    expect(levelLabel(1, 'fr').title).toBe('Expliquer')
    expect(levelLabel(2, 'fr').title).toBe('Préparer')
    expect(levelLabel(3, 'fr').title).toBe("Appliquer ce que j'ai autorisé")
    expect(levelLabel(2, 'en').title).toBe('Prepare')
    for (const n of levels) {
      expect(levelLabel(n, 'fr').text).toMatch(/\.$/)
      expect(levelLabel(n, 'en').text).not.toBe(levelLabel(n, 'fr').text)
    }
    expect(levelLabel(4, 'fr')).toBe(null)
    expect(levelLabel('x', 'fr')).toBe(null)
  })
})

describe('activityLine', () => {
  test('says in one line what the agent does', () => {
    expect(activityLine({ role: 'tool', text: 'Read src/Client.php' }, 'fr')).toBe("L'agent lit src/Client.php.")
    expect(activityLine({ role: 'tool', text: 'Edit composer.json' }, 'fr')).toBe("L'agent modifie composer.json.")
    expect(activityLine({ role: 'tool', text: 'Grep Guzzle' }, 'fr')).toBe("L'agent cherche dans le code.")
    expect(activityLine({ role: 'tool', text: 'mcp__michel__propose_fix' }, 'fr')).toBe("L'agent envoie sa proposition : Michel lance les tests sur la copie.")
    expect(activityLine({ role: 'tool', text: 'mcp__michel__propose_fix' }, 'en')).toBe('The agent sends its proposal: Michel runs the tests on the copy.')
    // The agent has no command tool (ruling 33): a stray one is only "working".
    expect(activityLine({ role: 'tool', text: 'Bash vendor/bin/phpunit' }, 'fr')).toBe("L'agent travaille.")
    expect(activityLine({ role: 'tool', text: 'Strange' }, 'en')).toBe('The agent is working.')
    expect(activityLine(null, 'fr')).toBe('')
  })
})

describe('mergeMessages', () => {
  test('a reconnect replays the conversation: each id once, in order', () => {
    let list = []
    list = mergeMessages(list, { id: 'm1', role: 'michel', text: 'a', at: '2026-10-30T10:00:00Z' })
    list = mergeMessages(list, { id: 'm2', role: 'agent', text: 'b', at: '2026-10-30T10:00:01Z' })
    list = mergeMessages(list, { id: 'm1', role: 'michel', text: 'a', at: '2026-10-30T10:00:00Z' })
    list = mergeMessages(list, { id: 'm0', role: 'user', text: 'c', at: '2026-10-30T09:59:59Z' })
    expect(list.map((m) => m.id)).toEqual(['m0', 'm1', 'm2'])
    expect(mergeMessages(list, null)).toBe(list)
  })
})

describe('splitMasked', () => {
  test('cuts the masked secrets out as whole tokens', () => {
    expect(splitMasked('key=[secret-ab12cd34-1] and [secret-ab12cd34-2].')).toEqual([
      { text: 'key=' }, { secret: '[secret-ab12cd34-1]' }, { text: ' and ' }, { secret: '[secret-ab12cd34-2]' }, { text: '.' },
    ])
    expect(splitMasked('nothing')).toEqual([{ text: 'nothing' }])
    expect(splitMasked('')).toEqual([])
  })
})

describe('stateLine', () => {
  test('says where a line of the list stands, in Michel\'s voice', () => {
    expect(stateLine({ kind: 'finding' }, 'fr')).toBe('Pas encore de correction.')
    expect(stateLine({ kind: 'attempt', attempt: { state: 'proposed' } }, 'fr')).toBe('Une correction attend ta validation.')
    expect(stateLine({ kind: 'attempt', attempt: { state: 'applied', branch: 'michel/fix-01abc' } }, 'en')).toBe('Branch michel/fix-01abc is ready.')
  })
})

describe('fixRoute', () => {
  test('reads and writes the Fix page addresses', () => {
    expect(fixRoute('#/fix')).toEqual({ attempt: '', finding: '' })
    expect(fixRoute('#/fix/01ABC')).toEqual({ attempt: '01ABC', finding: '' })
    expect(fixRoute('#/fix?finding=f%201')).toEqual({ attempt: '', finding: 'f 1' })
    expect(fixRoute('#/sources')).toBe(null)
    expect(fixRoute('#/fixes')).toBe(null)
    expect(fixHash({ attempt: '01ABC' })).toBe('#/fix/01ABC')
    expect(fixHash({ finding: 'f 1' })).toBe('#/fix?finding=f%201')
    expect(fixHash()).toBe('#/fix')
  })
})

describe('selectAction', () => {
  const attempts = [{ id: 'a2', finding: { id: 'f1' } }, { id: 'a1', finding: { id: 'f1' } }]

  test('opens an attempt unless it is the one shown or on its way', () => {
    expect(selectAction({ attempt: 'a1', finding: '' }, null, attempts)).toEqual({ kind: 'open', id: 'a1' })
    expect(selectAction({ attempt: 'a1', finding: '' }, 'a1', attempts)).toEqual({ kind: 'keep', id: 'a1' })
    // A then B then A: B is on its way, so A is opened again.
    expect(selectAction({ attempt: 'a1', finding: '' }, 'b1', attempts)).toEqual({ kind: 'open', id: 'a1' })
  })

  test('a finding already tried goes to its newest attempt', () => {
    expect(selectAction({ attempt: '', finding: 'f1' }, null, attempts)).toEqual({ kind: 'redirect', id: 'a2' })
    expect(selectAction({ attempt: '', finding: 'f9' }, 'a1', attempts)).toEqual({ kind: 'finding', id: 'f9' })
    expect(selectAction({ attempt: '', finding: '' }, 'a1', attempts)).toEqual({ kind: 'none', id: '' })
    expect(selectAction(null, null, null)).toEqual({ kind: 'none', id: '' })
  })
})

describe('acceptResult', () => {
  test('drops a late answer: page gone, or another attempt asked since', () => {
    expect(acceptResult({ alive: true, pending: 'a1' }, 'a1')).toBe(true)
    expect(acceptResult({ alive: false, pending: 'a1' }, 'a1')).toBe(false)
    expect(acceptResult({ alive: true, pending: 'b1' }, 'a1')).toBe(false)
    expect(acceptResult({ alive: true, pending: null }, 'a1')).toBe(false)
  })
})
