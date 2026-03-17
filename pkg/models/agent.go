package models

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

// Agent stores the non-human identity state maintained by the kernel.
type Agent struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	Roles           []Role       `json:"roles"`
	Capabilities    []Capability `json:"capabilities"`
	ReputationScore float64      `json:"reputation_score"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

