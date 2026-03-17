package hash

import (
	"testing"
	"time"

	"vaos-kernel/pkg/models"
)

func TestHashIntentDeterministic(t *testing.T) {
	hasher := Hasher{}
	intent := models.IntentRequest{
		AgentID:    "agent-1",
		Action:     "deploy",
		Resource:   "cluster-a",
		Parameters: map[string]string{"region": "us", "env": "prod"},
		RequestedAt: time.Now(),
	}

	first, err := hasher.HashIntent(intent)
	if err != nil {
		t.Fatalf("hash intent: %v", err)
	}
	second, err := hasher.HashIntent(intent)
	if err != nil {
		t.Fatalf("hash intent second: %v", err)
	}
	if first != second {
		t.Fatalf("expected deterministic hash, got %q and %q", first, second)
	}
}

func TestHashIntentValidation(t *testing.T) {
	hasher := Hasher{}
	if _, err := hasher.HashIntent(models.IntentRequest{}); err == nil {
		t.Fatal("expected validation error")
	}
}

