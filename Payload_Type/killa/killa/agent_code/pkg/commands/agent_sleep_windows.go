//go:build windows

package commands

import (
	"time"
)

// AgentSleep sleeps for the specified duration using the evasive NtDelayExecution system call.
func AgentSleep(d time.Duration) {
	if IndirectSyscallsAvailable() {
		// NtDelayExecution takes delay in 100-nanosecond intervals.
		// A negative value specifies a relative time.
		delay := -(int64(d) / 100)

		status := IndirectNtDelayExecution(false, &delay)
		if status == 0 { // STATUS_SUCCESS
			return
		}
	}

	// Fallback
	time.Sleep(d)
}
