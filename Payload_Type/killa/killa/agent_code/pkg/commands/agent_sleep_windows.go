//go:build windows

package commands

import (
	"time"
)

// AgentSleep wraps time.Sleep with evasive indirect syscalls (NtDelayExecution) on Windows
func AgentSleep(d time.Duration) {
	if d <= 0 {
		return
	}

	if IndirectSyscallsAvailable() {
		// Calculate the delay interval in 100-nanosecond intervals.
		// A negative value specifies a relative time.
		interval := -int64(d / time.Nanosecond / 100)
		IndirectNtDelayExecution(false, &interval)
	} else {
		time.Sleep(d)
	}
}
