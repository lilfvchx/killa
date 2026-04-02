# Iteration: Agent Sleep Evasion

## Context
The current sleep mechanism (`time.Sleep` and `jitterSleep` in `exec_helpers.go`) relies on standard OS threading sleeps. On Windows, this translates directly to `Sleep` or `NtDelayExecution` calls that can be monitored by EDR tools via userland hooks or kernel callbacks.

## Technique
We will introduce `AgentSleep(d time.Duration)`, a specialized wrapper. On Windows, it will leverage evasive indirect syscalls (`NtDelayExecution`) as instructed by our memory: "When introducing sleep or delay mechanisms in the 'killa' agent codebase, use the `commands.AgentSleep(d time.Duration)` wrapper instead of standard `time.Sleep` to leverage evasive indirect syscalls (`NtDelayExecution`) on Windows."

## Reasoning
By bypassing user-mode API monitoring, we improve stealth and minimize the risk of behavioral detections when the agent or its tasks are deliberately pausing execution.

## Changes
1. Add `NtDelayExecution` to the `SyscallResolver` initialization (`indirect_syscalls_windows.go`).
2. Add `IndirectNtDelayExecution` in `indirect_syscalls_windows.go`.
3. Create `sleep_windows.go` (and `sleep_other.go`) to expose the `AgentSleep` wrapper.
4. Replace existing instances of `time.Sleep` (especially within `jitterSleep` and `sleep.go` if applicable) with `AgentSleep`.

## Validation
1. Verify `go build` passes on Windows and other OSs.
2. Ensure existing tests continue to pass.
