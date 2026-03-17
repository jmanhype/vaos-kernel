package models

import "time"

// Capability represents an action an agent can perform against a resource.
type Capability struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Role groups capabilities into a named permission set.
type Role struct {
	Name         string       `json:"name"`
	Description  string       `json:"description"`
	Capabilities []Capability `json:"capabilities"`
}

// AgentState represents the current state of an agent.
type AgentState int

const (
	AgentStateUnspecified AgentState = iota
	AgentStateIdle
	AgentStateThinking
	AgentStateWorking
	AgentStateError
	AgentStateTerminated
)

func (s AgentState) String() string {
	switch s {
	case AgentStateIdle:
		return "IDLE"
	case AgentStateThinking:
		return "THINKING"
	case AgentStateWorking:
		return "WORKING"
	case AgentStateError:
		return "ERROR"
	case AgentStateTerminated:
		return "TERMINATED"
	default:
		return "UNKNOWN"
	}
}

// Agent stores the non-human identity state maintained by the kernel.
type Agent struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	Persona         string       `json:"persona"`
	State           AgentState   `json:"state"`
	Roles           []Role       `json:"roles"`
	Capabilities    []Capability `json:"capabilities"`
	ReputationScore float64      `json:"reputation_score"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	LastActive      time.Time    `json:"last_active,omitempty"`
}

