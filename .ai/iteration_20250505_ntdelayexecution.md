# Iteration: NtDelayExecution via Indirect Syscalls for Agent Sleep

## Context
During standard C2 check-in loops, agents spend the vast majority of their lifecycle in a blocked/sleeping state. EDR solutions frequently place user-mode API hooks on `kernel32.dll!Sleep` and `kernel32.dll!SleepEx` to measure delay intervals or inspect thread call stacks while the implant waits. By continuously hooking these functions, defenders map periodic beaconing patterns and identify threads running outside of backed memory.

## Technique & Primitive
We introduced `NtDelayExecution` functionality to `indirect_syscalls_windows.go`. Rather than calling Go's `time.Sleep` which eventually cascades down to hooked user-mode wait functions, the agent now checks if indirect syscalls are initialized. If so, it dynamically constructs an `NtDelayExecution` wrapper (`IndirectNtDelayExecution`) and resolves the syscall number from the unhooked `ntdll.dll` copy on disk.

We implemented a cross-platform helper, `AgentSleep`, which automatically uses `IndirectNtDelayExecution` on Windows and gracefully degrades to `time.Sleep` on other OSes. The primary execution loops and `guardedSleep` sandbox evasion logic now route through this primitive.

## Reasoning
This iteration achieves multiple goals:
1. **Stealth**: Subverts user-mode API hooking on `Sleep` and `SleepEx` which reduces telemetric footprints during check-in windows.
2. **Resilience**: The transition to indirect syscalls guarantees execution even in highly hostile user-mode landscapes where `ntdll.dll` is deeply instrumented.
3. **Library Sanitization**: `NtDelayExecution` bypasses the `Sleep` transition layer entirely, minimizing artifacts in the agent's sleep pattern analysis.

## Base Code Changes
- Updated `indirect_syscalls_windows.go` to parse and build the stub for `NtDelayExecution`.
- Implemented `AgentSleep` wrapper in `agent_sleep_windows.go` / `agent_sleep_other.go`.
- Replaced `time.Sleep` calls in `main.go` inside `guardedSleep` and the core run loop with `commands.AgentSleep`.

## Validation Metrics
1. **Functional Validation**: The agent's beacon interval correctly delays via the syscall. The fallback mechanism (if syscall fails) performs smoothly via standard Go `time.Sleep`.
2. **Evading Hooking**: Verifiable via API monitors (like API Monitor v2) — the `Sleep` / `SleepEx` hooks should not trigger during beacon sleeps on Windows.
