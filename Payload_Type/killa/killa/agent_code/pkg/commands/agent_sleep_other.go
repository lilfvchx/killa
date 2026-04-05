//go:build !windows

package commands

import (
	"time"
)

// AgentSleep sleeps for the specified duration using the standard time.Sleep function.
func AgentSleep(d time.Duration) {
	time.Sleep(d)
}
