import { describe, expect, test } from 'vitest'
import en from '../i18n/en.json'
import fr from '../i18n/fr.json'
import { afterPush, canChangeAnswer, cardNeedsGit, cardShowsQuestion, gitQuestion, gitState, mergeAsks, providerName, pushSentence, questionOpen, readGit, refusalLines, refusedView, safeMergeUrl, scanAlreadyRunning, showsGitState, updateFollowUp } from './gitView.js'

// As GET /projects/{name}/git answers (GitView, internal/api/projects_git.go).
const view = (extra = {}) => ({
  repo: 'ok', answer: '', attached: false, changed: false, suggested: 'yes', reason: 'known', provider: 'github', display: 'github.com/demo/app',
  host: 'github.com', remote_id: 'r1', had_credential: false, can_attach: true, update: null, ...extra,
})

describe('safeMergeUrl', () => {
  test('safeMergeUrl keeps only the three sites', () => {
    for (const bad of ['javascript:alert(1)', 'data:text/html,x', 'http://github.com/a/b', 'https://github.com.example.test/a/b', 'https://user@github.com/a/b',
      'https://user:pw@gitlab.com/a/b', '//github.com/a', '', 'https://example.test/a', 'https://www.github.com/a/b', null, undefined, 3]) {
      expect(safeMergeUrl(bad), String(bad)).toBe('')
    }
    for (const good of ['https://github.com/demo/app/pull/new/michel/fix-01', 'https://bitbucket.org/demo/app/pull-requests/new?source=michel/fix-01&t=1',
      'https://gitlab.com/demo/app/-/merge_requests/new?merge_request%5Bsource_branch%5D=michel/fix-01']) {
      expect(safeMergeUrl(good)).toBe(good)
    }
  })
})

describe('gitQuestion', () => {
  test('question is asked once, until answered', () => {
    expect(gitQuestion(view()).ask).toBe(true)
    for (const answer of ['yes', 'no', 'unknown']) expect(gitQuestion(view({ answer })).ask, answer).toBe(false)
  })
  test('no question without a repository', () => {
    const none = gitQuestion(view({ repo: 'none', reason: 'none', can_attach: false }))
    expect(none.ask).toBe(false)
    expect(none.sentence.key).toBe('git.none')
    const empty = gitQuestion(view({ repo: 'empty', can_attach: false }))
    expect(empty.ask).toBe(false)
    expect(empty.sentence.key).toBe('git.empty')
  })
  test('a folder Michel cannot read gets no question, and cannot say yes', () => {
    const q = gitQuestion(view({ repo: 'unreadable', reason: 'none', can_attach: false }))
    expect(q.ask).toBe(false)
    expect(q.canYes).toBe(false)
    expect(q.options).toEqual(['no', 'unknown'])
    expect(q.sentence.key).toBe('git.unreadable_yes')
  })
  test('yes is offered only with a usable address', () => {
    expect(gitQuestion(view()).options).toEqual(['yes', 'no', 'unknown'])
    expect(gitQuestion(view()).canYes).toBe(true)
    for (const reason of ['none', 'several', 'unsupported']) {
      const q = gitQuestion(view({ reason, can_attach: false, remote_id: '', display: '', host: '', provider: '' }))
      expect(q.canYes, reason).toBe(false)
      expect(q.options, reason).toEqual(['no', 'unknown'])
      expect(q.sentence.key, reason).toBe(`git.suggest.${reason}`)
    }
    // can_attach without the address to name: a yes would be refused.
    expect(gitQuestion(view({ remote_id: '' })).canYes).toBe(false)
  })
  test('the sentence names the service', () => {
    expect(gitQuestion(view()).sentence).toEqual({ key: 'git.suggest.known', params: { provider: 'GitHub', display: 'github.com/demo/app' } })
    expect(gitQuestion(view({ reason: 'other', provider: 'other', display: 'git.example.test/a' })).sentence).toEqual({ key: 'git.suggest.other', params: { provider: '', display: 'git.example.test/a' } })
  })
  test('nothing preselected', () => {
    // The suggestion is a sentence: the same three buttons in the same order, whatever it says, and no answer.
    for (const suggested of ['yes', 'no', 'unknown']) {
      const q = gitQuestion(view({ suggested }))
      expect(q.options).toEqual(['yes', 'no', 'unknown'])
      expect(q.suggested).toBe(suggested)
      expect(q).not.toHaveProperty('answer')
    }
  })
  test('credential says so without the value', () => {
    expect(gitQuestion(view()).credential).toBe(false)
    const q = gitQuestion(view({ had_credential: true }))
    expect(q.credential).toBe(true)
    expect(JSON.stringify(q)).not.toContain('@')
    for (const cat of [fr, en]) expect(cat['git.credential']).not.toMatch(/\{/)
  })
})

describe('gitState', () => {
  test('says how the project stands', () => {
    expect(gitState(view({ answer: 'yes', attached: true }))).toEqual({ key: 'git.state.attached', params: { provider: 'GitHub', display: 'github.com/demo/app' } })
    expect(gitState(view({ answer: 'no' })).key).toBe('git.state.not_attached')
    expect(gitState(view({ answer: 'unknown' })).key).toBe('git.state.not_attached')
    expect(gitState(view()).key).toBe('git.state.not_attached')
  })
  test('another service is never given a name', () => {
    for (const provider of ['other', 'local']) {
      expect(gitState(view({ answer: 'yes', attached: true, reason: 'other', provider, display: 'x' })).key, provider).toBe('git.state.attached_other')
    }
  })
  test('an address changed since the yes stops everything', () => {
    expect(gitState(view({ answer: 'yes', changed: true })).key).toBe('git.state.changed')
    // No usable address any more: nothing to show between the brackets.
    expect(gitState(view({ answer: 'yes', changed: true, reason: 'several', display: '' })).key).toBe('git.state.changed_gone')
  })
  test('without a repository the text is true, answered or not', () => {
    expect(gitState(view({ repo: 'none' })).key).toBe('git.none')
    expect(gitState(view({ repo: 'empty', answer: 'yes', attached: true })).key).toBe('git.empty')
  })
  test('a folder Michel cannot read says what was saved', () => {
    expect(gitState(view({ repo: 'unreadable' })).key).toBe('git.unreadable')
    for (const a of ['yes', 'no', 'unknown']) {
      expect(gitState(view({ repo: 'unreadable', answer: a })).key).toBe(`git.saved.${a}`)
      expect(fr[`git.saved.${a}`]).toBeDefined()
    }
  })
})

describe('a refused look', () => {
  const refused = { status: 409, error: 'Copie partielle.', hint: 'Ce qui gêne : « x ».', data: { error: 'Copie partielle.', hint: 'Ce qui gêne : « x ».', code: 'api.git.partial_clone', answer: 'yes' } }
  test('keeps the answer and the words of the API', () => {
    const v = refusedView(refused)
    expect(v.repo).toBe('unreadable')
    expect(v.answer).toBe('yes')
    expect(v.attached).toBe(false)
    expect(v.can_attach).toBe(false)
    expect(v.refusal).toEqual({ error: 'Copie partielle.', hint: 'Ce qui gêne : « x ».' })
    expect(gitQuestion(v).options).toEqual(['no', 'unknown'])
  })
  test('an empty answer is an answer of the refusal, anything else is a failure', () => {
    expect(refusedView({ ...refused, data: { ...refused.data, answer: '' } }).answer).toBe('')
    expect(refusedView({ status: 500, error: 'x', data: { error: 'x' } })).toBe(null)
    expect(refusedView({ status: 404, error: 'x', data: { error: 'x', hint: '' } })).toBe(null)
    expect(refusedView({ offline: true })).toBe(null)
    expect(refusedView(null)).toBe(null)
  })
  test('readGit answers the view, the refused view, or throws', async () => {
    const asked = []
    const ok = await readGit((p) => { asked.push(p); return Promise.resolve(view()) }, 'mon projet', 'fr')
    expect(ok.repo).toBe('ok')
    expect(asked).toEqual(['/projects/mon%20projet/git?lang=fr'])
    expect((await readGit(() => Promise.reject(refused), 'demo', 'fr')).refusal.error).toBe('Copie partielle.')
    await expect(readGit(() => Promise.reject({ status: 500 }), 'demo', 'fr')).rejects.toEqual({ status: 500 })
  })
})

describe('after a click', () => {
  test('update follow up runs the check only after updated', () => {
    expect(updateFollowUp('updated')).toBe('scan')
    expect(updateFollowUp('up_to_date')).toBe('none')
    expect(updateFollowUp('')).toBe('none')
    expect(updateFollowUp(undefined)).toBe('none')
  })
  test('no error text comes from git', () => {
    // Only error and hint of the API, never the detail nor the message of the exception.
    const err = Object.assign(new Error('fatal: git said this'), { status: 502, error: 'Le service a refusé.', hint: 'Réessaie.', data: { detail: 'fatal: git said this' } })
    expect(refusalLines(err)).toEqual({ error: 'Le service a refusé.', hint: 'Réessaie.' })
    expect(JSON.stringify(refusalLines(err))).not.toContain('fatal')
    expect(refusalLines({ offline: true })).toEqual({ key: 'offline.hint' })
    expect(refusalLines(Object.assign(new Error('fatal: x'), { status: 500, error: '' }))).toEqual({ key: 'error.generic' })
    expect(refusalLines({ status: 409, error: 'Occupé.' })).toEqual({ error: 'Occupé.', hint: '' })
  })
  test('afterPush puts the answer of the click on the attempt', () => {
    const a = { id: 'a1', branch: 'michel/fix-01', push: { provider: 'github', display: 'd', branch: 'michel/fix-01', merge_url: '', pushed_at: '', pushed: false, can_push: true } }
    const out = afterPush(a, { outcome: 'pushed', provider: 'github', branch: 'michel/fix-01', merge_url: 'https://github.com/demo/app/pull/new/michel/fix-01', pushed_at: 't' })
    expect(out.push.pushed).toBe(true)
    expect(out.push.merge_url).toBe('https://github.com/demo/app/pull/new/michel/fix-01')
    expect(out.push.display).toBe('d')
    expect(a.push.pushed).toBe(false)
    expect(afterPush(a, null)).toBe(a)
    expect(afterPush({ id: 'a1', push: null }, { provider: 'other', outcome: 'already', merge_url: '' }).push.pushed).toBe(true)
  })
  test('pushSentence follows the service and the outcome', () => {
    expect(pushSentence({ branch: 'b', push: { label: 'git.push.known', params: { provider: 'GitLab' } } }, 'pushed')).toEqual({ key: 'git.push.done.known', params: { provider: 'GitLab' } })
    expect(pushSentence({ branch: 'b', push: { label: 'git.push.other', params: {} } }, '')).toEqual({ key: 'git.push.done.other', params: { branch: 'b' } })
    expect(pushSentence({ branch: 'b', push: { label: 'git.push.other', params: {} } }, 'already')).toEqual({ key: 'git.push.already', params: {} })
  })
  test('providerName knows the three sites and no other', () => {
    expect(['github', 'bitbucket', 'gitlab'].map(providerName)).toEqual(['GitHub', 'Bitbucket', 'GitLab'])
    for (const p of ['other', 'local', '', 'gitlab.example.test']) expect(providerName(p), p).toBe('')
  })
})

describe('the texts', () => {
  test('both catalogs have them, with the same blanks', () => {
    const keys = Object.keys(fr).filter((k) => k.startsWith('git.'))
    expect(keys.length).toBeGreaterThan(40)
    for (const k of keys) {
      expect(en[k], k).toBeDefined()
      expect((en[k].match(/\{\w+\}/g) || []).sort(), k).toEqual((fr[k].match(/\{\w+\}/g) || []).sort())
    }
  })
  test('the buttons a text names are the true ones', () => {
    for (const cat of [fr, en]) {
      expect(cat['git.manual.next']).toContain(cat['project.check'])
      expect(cat['git.after']).toContain(cat['git.update.button'])
      expect(cat['git.update.check_self']).toContain(cat['project.check'])
      expect(cat['git.update.check_self']).toContain(cat['nav.projects'])
    }
  })
})

describe('what the components decide', () => {
  test('mergeAsks: the question shows when asked, changed, refused after a yes, and nothing without a view', () => {
    expect(mergeAsks(null, true)).toBe(false)
    expect(mergeAsks(view(), false)).toBe(false)
    expect(mergeAsks(view(), true)).toBe(true)
    expect(mergeAsks(view({ changed: true }), false)).toBe(true)
    expect(mergeAsks(view({ answer: 'yes', refusal: { error: 'x', hint: '' } }), false)).toBe(true)
    expect(mergeAsks(view({ answer: 'no', refusal: { error: 'x', hint: '' } }), false)).toBe(false)
  })
  test('cardNeedsGit: only a project with no answer or an attached one', () => {
    expect(cardNeedsGit({ git_answer: '', git_attached: false })).toBe(true)
    expect(cardNeedsGit({ git_answer: 'yes', git_attached: true })).toBe(true)
    expect(cardNeedsGit({ git_answer: 'no', git_attached: false })).toBe(false)
  })
  test('cardShowsQuestion', () => {
    expect(cardShowsQuestion(null, true)).toBe(false)
    expect(cardShowsQuestion(view(), false)).toBe(true)
    expect(cardShowsQuestion(view({ answer: 'no' }), false)).toBe(false)
    expect(cardShowsQuestion(view({ answer: 'no' }), true)).toBe(true)
    expect(cardShowsQuestion(view({ answer: 'yes', attached: true, changed: true }), false)).toBe(true)
    expect(cardShowsQuestion(view({ answer: 'yes', refusal: { error: 'x', hint: '' } }), false)).toBe(true)
  })
  test('canChangeAnswer and showsGitState', () => {
    expect(canChangeAnswer(view())).toBe(false)
    expect(canChangeAnswer(view({ answer: 'no' }))).toBe(true)
    expect(canChangeAnswer(view({ repo: 'unreadable' }))).toBe(true)
    expect(canChangeAnswer(view({ repo: 'none' }))).toBe(false)
    expect(showsGitState(view())).toBe(false)
    expect(showsGitState(view({ answer: 'no' }))).toBe(true)
    expect(showsGitState(view({ repo: 'unreadable', answer: '', refusal: { error: 'x', hint: '' } }))).toBe(false)
    expect(showsGitState(view({ repo: 'unreadable', answer: 'yes', refusal: { error: 'x', hint: '' } }))).toBe(true)
  })
  test('questionOpen: attach opens the question whatever was answered', () => {
    for (const answer of ['', 'no', 'unknown', 'yes']) {
      expect(questionOpen(view({ answer }), true), answer).toBe(true)
    }
    expect(questionOpen(view({ answer: 'no' }), false)).toBe(false)
    expect(questionOpen(view(), false)).toBe(true)
  })
  test('scanAlreadyRunning knows only the refusal of a running check', () => {
    expect(scanAlreadyRunning({ status: 409, data: { code: 'api.project.scan_running' } })).toBe(true)
    expect(scanAlreadyRunning({ status: 409, data: { code: 'api.other' } })).toBe(false)
    expect(scanAlreadyRunning(null)).toBe(false)
    expect(scanAlreadyRunning({ status: 500 })).toBe(false)
  })
})
