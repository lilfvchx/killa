//go:build windows

package commands

import (
	"time"
)

// AgentSleep performs an evasive sleep using indirect syscalls to NtDelayExecution on Windows.
func AgentSleep(d time.Duration) {
	if !IndirectSyscallsAvailable() {
		time.Sleep(d)
		return
	}

	// NtDelayExecution expects a 100-nanosecond interval.
	// Negative values specify a relative sleep time.
	delay := int64(-d.Nanoseconds() / 100)

	status := IndirectNtDelayExecution(0, &delay)
	if status != 0 {
		// Fallback to standard sleep if NtDelayExecution fails
		time.Sleep(d)
	}
}
