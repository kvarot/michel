package fix

import (
	"errors"

	"github.com/kvarot/michel/internal/agent"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/workcopy"
)

// The refusals of the fix service. Each one is a typed error with a
// catalog key (Explain renders it in the user's language); the English text
// is for logs.
var (
	// ErrNotGit: the project folder is not a git repository. The brief
	// stays available.
	ErrNotGit = errors.New("this project is not in git: Michel cannot prepare a fix")
	// ErrConsentRequired: the project never gave its AI consent (or a host
	// of the consent has no allow rule any more).
	ErrConsentRequired = errors.New("the project's AI consent is needed first")
	// ErrHealthForbidden: a project classified health never goes to an
	// external AI, consent or not.
	ErrHealthForbidden = errors.New("a project classified health never goes to an external AI")
	// ErrStrictLocal: the policy is strict_local; the mode is a user choice
	// Michel never changes.
	ErrStrictLocal = errors.New("the policy is strict_local: external providers stay off")
	// ErrAgentUnavailable: Claude Code is missing, too old or not logged
	// in (AgentUnavailableError carries the status).
	ErrAgentUnavailable = errors.New("Claude Code cannot be used")
	// ErrBusy: an attempt is being worked on or waits for the user on
	// this project.
	ErrBusy = errors.New("a fix attempt is already running on this project")
	// ErrStaleProposal: the hash approved is not the current proposal's.
	ErrStaleProposal = errors.New("the proposal changed since it was shown")
	// ErrMaskToken: the change holds a [secret-...] token; Michel never
	// puts one in a branch.
	ErrMaskToken = errors.New("the change holds a masked secret token")
	// ErrNoChange: the copy holds no change to propose.
	ErrNoChange = errors.New("the copy holds no change to propose")
	// ErrNoProposal: the attempt has no proposal to approve.
	ErrNoProposal = errors.New("the attempt has no proposal")
	// ErrAgentGone: the agent's session has ended; no message reaches it.
	ErrAgentGone = errors.New("the agent's session has ended")
	// ErrChangeRefused wraps a refusal of the change by the work copy
	// (outside the copy, excluded file, binary text, too large): the
	// attempt failed.
	ErrChangeRefused = errors.New("Michel refused the change")
	// ErrHoldStale: the answer to a held attempt is not about what the agent
	// would read now. No agent started.
	ErrHoldStale = errors.New("the code changed since Michel searched it for keys")
	// ErrHoldPerson: only a person answers a held attempt.
	ErrHoldPerson = errors.New("only a person can answer a held fix attempt")

	// The refusals of a click on a remote. A failure of git itself is a
	// *workcopy.GitFailure, read the same way.

	// ErrGitNoRepo: the project's folder is not a Git repository.
	ErrGitNoRepo = errors.New("this folder is not a Git repository")
	// ErrGitEmptyRepo: the repository holds no commit yet.
	ErrGitEmptyRepo = errors.New("this Git repository holds no commit yet")
	// ErrGitNotAttached: the project did not answer yes.
	ErrGitNotAttached = errors.New("this project is not attached to a Git service")
	// ErrGitNoRemote: no address Michel can use.
	ErrGitNoRemote = errors.New("no usable address in this project")
	// ErrGitRemoteChanged: the address is not the one the person agreed to.
	ErrGitRemoteChanged = errors.New("the project's address changed since the answer")
	// ErrGitNoRule: the network rule of the host is gone.
	ErrGitNoRule = errors.New("the network rule of this Git service was removed")
	// ErrGitBranchMoved: the fix has no commit to send.
	ErrGitBranchMoved = errors.New("the fix's branch changed or no longer exists")
	// ErrGitBusy: a click or a check holds this project.
	ErrGitBusy = errors.New("Michel is already working on this folder")
	// ErrGitNotApplied: the attempt has no branch to send.
	ErrGitNotApplied = errors.New("this fix has no branch to send")
	// ErrGitSentNotNoted: the branch left, and Michel could not note it (the
	// row of the push or the audit log). It matches with errors.Is next to the
	// cause, which stays in the log and never reaches the page.
	ErrGitSentNotNoted = errors.New("the branch was sent, but Michel could not note it")
)

// gitSentinels are the catalog keys of the refusals of a click.
var gitSentinels = []struct {
	err error
	key string
}{
	{ErrGitNoRepo, "api.git.no_repo"},
	{ErrGitEmptyRepo, "api.git.empty_repo"},
	{ErrGitNotAttached, "api.git.not_attached"},
	{ErrGitNoRemote, "api.git.no_remote"},
	{ErrGitRemoteChanged, "api.git.remote_changed"},
	{ErrGitNoRule, "api.git.no_rule"},
	{ErrGitBranchMoved, "api.git.branch_moved"},
	{ErrGitBusy, "api.git.busy"},
	{ErrGitNotApplied, "api.git.not_applied"},
	{ErrGitSentNotNoted, "api.git.sent_not_noted"},
}

// gitErrorKey is the catalog key of a refusal of a click, "" for any other error. A
// class without a sentence reads as failed, never as a raw key.
func gitErrorKey(err error) string {
	var gf *workcopy.GitFailure
	if errors.As(err, &gf) {
		if key := "api.git." + gf.Class; i18n.Has(key) {
			return key
		}
		return "api.git.failed"
	}
	for _, s := range gitSentinels {
		if errors.Is(err, s.err) {
			return s.key
		}
	}
	return ""
}

// AgentUnavailableError says why Claude Code cannot be used. It matches
// ErrAgentUnavailable with errors.Is.
type AgentUnavailableError struct{ Status agent.Status }

func (e *AgentUnavailableError) Error() string {
	return ErrAgentUnavailable.Error() + ": " + e.Status.Hint
}
func (e *AgentUnavailableError) Is(target error) bool { return target == ErrAgentUnavailable }

// ErrorKey is the catalog key of a refusal, "" for any other error.
func ErrorKey(err error) string {
	switch {
	case err == nil:
		return ""
	case serverErrorKey(err) != "":
		return serverErrorKey(err)
	case gitErrorKey(err) != "":
		return gitErrorKey(err)
	case errors.Is(err, ErrNotGit):
		return "fix.err.not_git"
	case errors.Is(err, ErrConsentRequired):
		return "fix.err.consent_required"
	case errors.Is(err, ErrHealthForbidden):
		return "fix.err.health_forbidden"
	case errors.Is(err, ErrStrictLocal):
		return "fix.err.strict_local"
	case errors.Is(err, ErrAgentUnavailable):
		return "fix.err.agent_unavailable"
	case errors.Is(err, ErrBusy):
		return "fix.err.busy"
	case errors.Is(err, ErrStaleProposal):
		return "fix.err.stale_proposal"
	case errors.Is(err, ErrMaskToken):
		return "fix.err.mask_token"
	case errors.Is(err, ErrNoChange):
		return "fix.err.no_change"
	case errors.Is(err, ErrNoProposal):
		return "fix.err.no_proposal"
	case errors.Is(err, ErrAgentGone):
		return "fix.err.agent_gone"
	case errors.Is(err, ErrChangeRefused):
		return "fix.err.change_refused"
	case errors.Is(err, ErrHoldStale):
		return "fix.err.hold_stale"
	case errors.Is(err, ErrHoldPerson):
		return "fix.err.hold_person"
	case errors.Is(err, ErrNotAwaiting):
		return "fix.err.not_awaiting"
	case errors.Is(err, ErrNoTree):
		return "fix.err.no_tree"
	case errors.Is(err, ErrTestsInterrupted):
		return "fix.err.tests_interrupted"
	case errors.Is(err, ErrTestsRunning):
		return "fix.err.tests_running"
	case errors.Is(err, ErrBadTransition):
		return "fix.err.bad_state"
	case errors.Is(err, ErrNotFound):
		return "fix.err.not_found"
	}
	return ""
}

// Explain renders a refusal in lang (the hint of Claude Code added for
// ErrAgentUnavailable); "" for an error that is not a refusal.
func Explain(lang i18n.Lang, err error) string {
	if !lang.Valid() {
		lang = i18n.EN
	}
	var text string
	switch ErrorKey(err) {
	case "":
		return ""
	case "api.git.not_default":
		var gf *workcopy.GitFailure
		errors.As(err, &gf)
		text = i18n.T(lang, "api.git.not_default", gf.Current, gf.Default)
	case "fix.err.not_git":
		text = i18n.T(lang, "fix.err.not_git")
	case "fix.err.consent_required":
		text = i18n.T(lang, "fix.err.consent_required")
	case "fix.err.health_forbidden":
		text = i18n.T(lang, "fix.err.health_forbidden")
	case "fix.err.strict_local":
		text = i18n.T(lang, "fix.err.strict_local")
	case "fix.err.agent_unavailable":
		text = i18n.T(lang, "fix.err.agent_unavailable")
		var ae *AgentUnavailableError
		if errors.As(err, &ae) {
			if hint := ae.Status.Message(lang); hint != "" {
				text += " " + hint
			}
		}
	case "fix.err.busy":
		text = i18n.T(lang, "fix.err.busy")
	case "fix.err.stale_proposal":
		text = i18n.T(lang, "fix.err.stale_proposal")
	case "fix.err.mask_token":
		text = i18n.T(lang, "fix.err.mask_token")
	case "fix.err.no_change":
		text = i18n.T(lang, "fix.err.no_change")
	case "fix.err.no_proposal":
		text = i18n.T(lang, "fix.err.no_proposal")
	case "fix.err.agent_gone":
		text = i18n.T(lang, "fix.err.agent_gone")
	case "fix.err.change_refused":
		text = i18n.T(lang, "fix.err.change_refused")
	case "fix.err.hold_stale":
		text = i18n.T(lang, "fix.err.hold_stale")
	case "fix.err.hold_person":
		text = i18n.T(lang, "fix.err.hold_person")
	case "fix.err.not_awaiting":
		text = i18n.T(lang, "fix.err.not_awaiting")
	case "fix.err.no_tree":
		text = i18n.T(lang, "fix.err.no_tree")
	case "fix.err.tests_interrupted":
		text = i18n.T(lang, "fix.err.tests_interrupted")
	case "fix.err.tests_running":
		text = i18n.T(lang, "fix.err.tests_running")
	case "fix.err.bad_state":
		text = i18n.T(lang, "fix.err.bad_state")
	case "fix.err.not_found":
		text = i18n.T(lang, "fix.err.not_found")
	default:
		// fix.server.*: the text of the key as it is.
		text = i18n.T(lang, ErrorKey(err))
	}
	return text
}
