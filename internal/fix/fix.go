// Package fix stores the attempts of the fix agent: the work Michel asks an
// agent to do on a copy of a project, what the agent proposes, the
// conversation around it, and the queue of automatic attempts.
package fix

import (
	"errors"
	"time"

	"github.com/kvarot/michel/internal/workcopy"
)

// State is where a fix attempt stands.
type State string

// The states of an attempt.
const (
	StatePreparing    State = "preparing"
	StateProposed     State = "proposed"
	StateApproved     State = "approved"
	StateRefused      State = "refused"
	StateApplied      State = "applied"
	StateProvenFixed  State = "proven_fixed"
	StateInconclusive State = "inconclusive"
	StateFailed       State = "failed"
	StateSuperseded   State = "superseded"
)

// Origin says who started an attempt.
const (
	OriginAgent     = "agent.claude"      // on request of the user
	OriginAgentAuto = "agent.claude.auto" // started alone (fix level 2)
	OriginManual    = "manual"            // done by hand by the user
)

// Roles of a conversation message.
const (
	RoleUser   = "user"
	RoleAgent  = "agent"
	RoleMichel = "michel"
	// RoleTool is a tool the agent used (its name and a short summary), a
	// line of progress rather than of conversation.
	RoleTool = "tool"
)

var (
	// ErrBadTransition is returned when an attempt is not in a state the
	// change allows.
	ErrBadTransition = errors.New("the fix attempt is not in a state that allows this change")
	// ErrNotFound is returned for an unknown attempt.
	ErrNotFound = errors.New("fix attempt not found")
)

// Attempt is one try to fix one finding.
type Attempt struct {
	ID        string `json:"id"`
	FindingID string `json:"finding_id"`
	ProjectID string `json:"project_id"`
	Origin    string `json:"origin"`
	State     State  `json:"state"`
	// CloneDir is the work copy, a local path: never sent out.
	CloneDir  string `json:"-"`
	SessionID string `json:"session_id"`
	Cause     string `json:"cause"`
	// CauseDetail is the short technical detail behind Cause (sanitized:
	// no path, no secret), "" when there is none.
	CauseDetail string    `json:"cause_detail"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	// ApprovedBy is who approved the current proposal ("auto" when a level
	// 3 rule did), "" before.
	ApprovedBy string `json:"approved_by"`
	// ApprovedProposal and ApprovedHash name the proposal the approval was
	// given for: Apply applies that one and no other.
	ApprovedProposal string `json:"approved_proposal"`
	ApprovedHash     string `json:"approved_hash"`
	// Work is the work copy and the update plan of the attempt (local
	// paths: never sent out). WorkError is set when the stored record could
	// not be read: the attempt is listed, but has no usable copy.
	Work      Work   `json:"-"`
	WorkError string `json:"-"`
}

// Work is what the fix service keeps with an attempt: its copy and the
// validated update plan it runs when the agent proposes.
type Work struct {
	Copy workcopy.Copy `json:"copy"`
	// Mirror repeats Copy.Mirror, which the copy leaves out of JSON.
	Mirror string `json:"mirror"`
	Plan   Plan   `json:"plan"`
	// Tree0 is the tree of the copy right after Michel's own update, before
	// the agent touched anything: a proposal applied without a click must
	// commit that very tree (controller ruling 36).
	Tree0 string `json:"tree0"`
}

// Plan is the closed update Michel runs in the copy at proposal time,
// built from the finding and the brief at Start (never from free text).
type Plan struct {
	Ecosystem   string `json:"ecosystem"`
	ManifestRel string `json:"manifest_rel"`
	Package     string `json:"package"`
	Target      string `json:"target"`
	Jump        string `json:"jump"`
	// Update is the argv of the update command, empty when Michel has none
	// for this lockfile (yarn, pnpm, unknown target).
	Update []string `json:"update"`
}

// Proposal is what the agent proposes for an attempt. A newer proposal marks
// the previous ones Superseded.
type Proposal struct {
	ID          string   `json:"id"`
	AttemptID   string   `json:"attempt_id"`
	Summary     string   `json:"summary"`
	Diff        string   `json:"diff"`
	Files       []string `json:"files"`
	TestsStatus string   `json:"tests_status"`
	TestsOutput string   `json:"tests_output"`
	RescanClean bool     `json:"rescan_clean"`
	Risk        int      `json:"risk"`
	// Hash is the fingerprint the user approves: SHA-256 over the raw
	// patch, the fix commit, the tests status and the summary.
	Hash string `json:"hash"`
	// CommitSHA is the fix commit built in the private mirror.
	CommitSHA string `json:"commit_sha"`
	// DiffRaw is the exact patch the commit applies (hashed, checked for
	// mask tokens before apply, never shown).
	DiffRaw     []byte   `json:"-"`
	StepsServer []string `json:"steps_server"`
	// FromVersion is the package's version when the attempt started;
	// ToVersion the one the fix commit's lockfile resolves, else the
	// planned target ("" when unknown). Not covered by Hash: both follow
	// from the patch.
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	CreatedAt   time.Time `json:"created_at"`
	Superseded  bool      `json:"superseded"`
}

// ProposeInput is what the agent gives to the propose_fix tool. It lives
// here so that the fix service and the MCP server do not import each other.
type ProposeInput struct {
	Summary string `json:"summary"`
	Notes   string `json:"notes"`
}

// Message is one line of the conversation of an attempt.
type Message struct {
	ID        string    `json:"id"`
	AttemptID string    `json:"attempt_id"`
	Role      string    `json:"role"` // RoleUser, RoleAgent or RoleMichel
	Text      string    `json:"text"`
	At        time.Time `json:"at"`
}
