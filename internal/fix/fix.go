// Package fix stores the attempts of the fix agent: the work Michel asks an
// agent to do on a copy of a project, what the agent proposes, the
// conversation around it, and the queue of automatic attempts.
package fix

import (
	"errors"
	"time"
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
	CloneDir  string    `json:"-"`
	SessionID string    `json:"session_id"`
	Cause     string    `json:"cause"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
	// Hash is the fingerprint of the diff the user approves.
	Hash        string    `json:"hash"`
	StepsServer []string  `json:"steps_server"`
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
