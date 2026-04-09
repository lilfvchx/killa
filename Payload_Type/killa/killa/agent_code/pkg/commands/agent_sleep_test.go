package commands

import (
	"testing"
	"time"
)

func TestAgentSleep(t *testing.T) {
	start := time.Now()
	delay := 50 * time.Millisecond

	AgentSleep(delay)

	elapsed := time.Since(start)

	if elapsed < delay {
		t.Errorf("AgentSleep did not wait long enough. Expected at least %v, got %v", delay, elapsed)
	}
}
