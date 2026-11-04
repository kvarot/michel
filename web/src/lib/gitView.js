// Pure functions behind the Git question, the send button and the update button.
// No DOM and no state: what is read comes through a parameter. Shapes: GitView,
// GitViewRefused and GitPushResponse in internal/api/projects_git.go.

/** The only origins a link to a merge request may have (R21, R31). */
const mergeOrigins = ['https://github.com', 'https://bitbucket.org', 'https://gitlab.com']

const providerNames = { github: 'GitHub', bitbucket: 'Bitbucket', gitlab: 'GitLab' }

/**
 * providerName is how a site Michel recognises is written. Any other service,
 * and the local remote of the trial (R33), has no name here.
 * @param {string} provider
 * @returns {string} '' when it is not one of the three sites
 */
export function providerName(provider) {
  return Object.hasOwn(providerNames, provider) ? providerNames[provider] : ''
}

/**
 * safeMergeUrl is the link only if it goes in https to exactly one of the three
 * sites, without a user or a password. Go built it from checked parts: this is
 * checked again just before it is rendered, whatever the API answered.
 * @param {*} url
 * @returns {string} the link, '' otherwise
 */
export function safeMergeUrl(url) {
  if (typeof url !== 'string' || !url) return ''
  let u
  try {
    u = new URL(url)
  } catch {
    return ''
  }
  if (u.protocol !== 'https:' || u.username || u.password || !mergeOrigins.includes(u.origin)) return ''
  return u.href
}

/** suggestion is the sentence for what Michel read of the address. */
function suggestion(view) {
  const key = `git.suggest.${['known', 'other', 'none', 'several', 'unsupported'].includes(view.reason) ? view.reason : 'none'}`
  return { key, params: { provider: providerName(view.provider), display: view.display || '' } }
}

/**
 * gitQuestion is what the question says for a view. It is asked once, on a
 * repository with a commit, until it is answered. The suggestion is a sentence,
 * never an answer: no button differs from another because of it. A yes needs an
 * address to name.
 * @param {object} view GitView
 * @returns {{ask: boolean, sentence: {key: string, params: object}, suggested: string, options: string[], canYes: boolean, credential: boolean}}
 */
export function gitQuestion(view) {
  const canYes = !!view.can_attach && !!view.remote_id
  let sentence = suggestion(view)
  if (view.repo === 'none') sentence = { key: 'git.none', params: {} }
  else if (view.repo === 'empty') sentence = { key: 'git.empty', params: {} }
  else if (view.repo === 'unreadable') sentence = { key: 'git.unreadable_yes', params: {} }
  return {
    ask: view.repo === 'ok' && !view.answer,
    sentence,
    suggested: view.suggested,
    options: canYes ? ['yes', 'no', 'unknown'] : ['no', 'unknown'],
    canYes,
    credential: !!view.had_credential,
  }
}

/**
 * gitState is the sentence that says how a project stands with its Git service.
 * @param {object} view GitView
 * @returns {{key: string, params: object}}
 */
export function gitState(view) {
  if (view.repo === 'none') return { key: 'git.none', params: {} }
  if (view.repo === 'empty') return { key: 'git.empty', params: {} }
  if (view.repo === 'unreadable') return { key: view.answer ? `git.saved.${view.answer}` : 'git.unreadable', params: {} }
  // The address can be gone altogether (several, or one Michel cannot use).
  if (view.changed) return view.display ? { key: 'git.state.changed', params: { display: view.display } } : { key: 'git.state.changed_gone', params: {} }
  if (!view.attached) return { key: 'git.state.not_attached', params: {} }
  const provider = providerName(view.provider)
  if (provider) return { key: 'git.state.attached', params: { provider, display: view.display } }
  return { key: 'git.state.attached_other', params: { display: view.display } }
}

/**
 * refusedView is a refused GET /projects/{name}/git, as a view: the folder cannot
 * be read, and the person can still see and change what they answered. Only that
 * refusal carries answer: null for any other failure.
 * @param {*} err the ApiError
 * @returns {object|null}
 */
export function refusedView(err) {
  if (typeof err?.data?.answer !== 'string') return null
  return {
    repo: 'unreadable', answer: err.data.answer, attached: false, changed: false, suggested: 'unknown', reason: 'none', provider: '', display: '', host: '', remote_id: '',
    had_credential: false, can_attach: false, update: null, refusal: { error: err.error || '', hint: err.hint || '' },
  }
}

/**
 * readGit reads the view of a project: a refusal that carries the answer comes
 * back as a view, any other failure is thrown.
 * @param {(path: string) => Promise<object>} get api.get
 * @param {string} name
 * @param {string} lang
 * @returns {Promise<object>}
 */
export async function readGit(get, name, lang) {
  try {
    return await get(`/projects/${encodeURIComponent(name)}/git?lang=${encodeURIComponent(lang)}`)
  } catch (err) {
    const view = refusedView(err)
    if (!view) throw err
    return view
  }
}

/**
 * refusalLines is what a failed click shows: error and hint of the API, or a
 * sentence of the page. Never git's words, nor the message of the exception (R32).
 * @param {*} err the ApiError
 * @returns {{error: string, hint: string}|{key: string}}
 */
export function refusalLines(err) {
  if (err?.offline) return { key: 'offline.hint' }
  if (!err?.error) return { key: 'error.generic' }
  return { error: err.error, hint: err.hint || '' }
}

/**
 * updateFollowUp says what follows a click on the update button: only new files
 * are worth a check, which is what can prove the fix (R25).
 * @param {string} outcome
 * @returns {'scan'|'none'}
 */
export function updateFollowUp(outcome) {
  return outcome === 'updated' ? 'scan' : 'none'
}

/**
 * afterPush is the attempt with the answer of a click on the send button, so the
 * link shows even if reading the attempt again fails.
 * @param {object} attempt AttemptView
 * @param {object|null} res GitPushResponse
 * @returns {object}
 */
export function afterPush(attempt, res) {
  if (!res) return attempt
  return {
    ...attempt,
    push: { ...attempt.push, provider: res.provider, branch: res.branch, merge_url: res.merge_url, pushed_at: res.pushed_at, pushed: true },
  }
}

/**
 * pushSentence is what is said once the branch left.
 * @param {{branch: string, push: {label: string, params: object}}} step mergeStep()
 * @param {string} outcome the last click's, '' when the page found it already sent
 * @returns {{key: string, params: object}}
 */
export function pushSentence(step, outcome) {
  if (outcome === 'already') return { key: 'git.push.already', params: {} }
  if (step.push.params.provider) return { key: 'git.push.done.known', params: { provider: step.push.params.provider } }
  return { key: 'git.push.done.other', params: { branch: step.branch } }
}

/**
 * mergeAsks says whether the merge step shows the Git question: the person asked
 * for it, the address changed, or a yes that no longer holds.
 * @param {object|null} git GitView
 * @param {boolean} asking
 * @returns {boolean}
 */
export function mergeAsks(git, asking) {
  if (!git) return false
  return asking || git.changed || (!!git.refusal && git.answer === 'yes')
}

/**
 * cardNeedsGit says whether a project card reads the Git view: there is a question
 * to ask or a button to show.
 * @param {{git_answer?: string, git_attached?: boolean}} project element of GET /projects
 * @returns {boolean}
 */
export function cardNeedsGit(project) {
  return project.git_answer === '' || project.git_attached === true
}

/**
 * cardShowsQuestion says whether a project card shows the question: not yet
 * answered, answered just here, or an answer that no longer holds.
 * @param {object|null} git GitView
 * @param {boolean} answeredHere
 * @returns {boolean}
 */
export function cardShowsQuestion(git, answeredHere) {
  if (!git) return false
  return answeredHere || !git.answer || git.changed || (!!git.refusal && git.answer === 'yes')
}

/**
 * canChangeAnswer says whether "Changer ma réponse" shows. Without a repository and
 * without an answer there is nothing to answer about (R30).
 * @param {object} view GitView
 * @returns {boolean}
 */
export function canChangeAnswer(view) {
  return !gitQuestion(view).ask && (!!view.answer || view.repo === 'unreadable')
}

/**
 * showsGitState says whether the sentence of the state shows. A refusal already says
 * the folder cannot be read: without an answer nothing is left to say.
 * @param {object} view GitView
 * @returns {boolean}
 */
export function showsGitState(view) {
  return !gitQuestion(view).ask && !(view.refusal && !view.answer)
}

/**
 * questionOpen says whether the question itself is on screen: unanswered, or opened
 * by the person (changing), which includes "Rattacher ce projet" whatever was
 * answered before.
 * @param {object} view GitView
 * @param {boolean} changing
 * @returns {boolean}
 */
export function questionOpen(view, changing) {
  return gitQuestion(view).ask || changing
}

/**
 * scanAlreadyRunning is the refusal of a check started while one runs: the check
 * the person wants is there, so it is followed and not told as a failure.
 * @param {*} err the ApiError
 * @returns {boolean}
 */
export function scanAlreadyRunning(err) {
  return err?.data?.code === 'api.project.scan_running'
}

/**
 * sentNotNoted says a push refusal is the one where the branch did leave and
 * Michel could not note it: the page must not tell the person to answer No.
 * @param {*} err the ApiError
 * @returns {boolean}
 */
export function sentNotNoted(err) {
  return err?.data?.code === 'api.git.sent_not_noted'
}
