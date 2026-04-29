# Iteration: Evasive Sleep (NtDelayExecution)

## Technical Context
The `killa` agent currently uses the standard Go `time.Sleep` function across its codebase, including the core agent beacon loop (`main.go`) and various commands (e.g., `spray`, `exec`, `watch_dir`). Standard sleep mechanisms are heavily monitored by endpoint detection and response (EDR) agents and sandbox environments to detect periodic beaconing or delay-based evasion attempts. A common EDR heuristic is hooking high-level sleep APIs (like `Sleep` in kernel32.dll) or the underlying user-mode syscalls.

## Technique/Primitive
This iteration implements an evasive sleep mechanism for Windows using indirect syscalls to `NtDelayExecution`. By utilizing the existing `SyscallResolver` (TartarusGate logic) to resolve the syscall number and execute it via a dynamically allocated indirect stub (jumping to a `syscall; ret` gadget in `ntdll.dll`), we bypass user-mode API hooking entirely.

- **Windows Internals:** `NtDelayExecution` is the underlying NTAPI function for sleep operations. It accepts a 100-nanosecond interval where negative values denote a relative time delay.
- **Platform Agnostic:** We introduce a centralized wrapper, `commands.AgentSleep(d time.Duration)`, which abstracts the platform-specific logic. On non-Windows platforms (or if indirect syscalls fail/are unavailable), it falls back to standard `time.Sleep`.

## Reasoning
- **Stealth:** By avoiding standard sleep functions and executing `NtDelayExecution` via indirect syscalls, the agent's delays become invisible to user-mode hooks and telemetry mechanisms relying on standard API interception. This reduces the behavioral footprint.
- **Resilience:** The indirect syscall resolver dynamically finds syscall numbers and gadgets, making the implementation resilient against OS version changes and inline hooking.
- **Library Sanitization/Hygiene:** The agent operates cleanly without leaving predictable traces of sleep calls in user-mode APIs.

## Concrete Changes
1. Added `NtDelayExecution` to the `keyFunctions` array in `pkg/commands/indirect_syscalls_windows.go`.
2. Created the `IndirectNtDelayExecution` wrapper function in `pkg/commands/indirect_syscalls_windows.go`.
3. Created `pkg/commands/agentsleep_windows.go` (Windows implementation using `IndirectNtDelayExecution`) and `pkg/commands/agentsleep_other.go` (non-Windows fallback).
4. Replaced calls to `time.Sleep` with `commands.AgentSleep` in `main.go`, `pkg/commands/exec_helpers.go`, `pkg/commands/spray.go`, `pkg/commands/watch_dir.go`, `pkg/commands/pty_unix.go`, and `pkg/commands/ptrace_inject.go`.

## Validation
- **Compilation:** Ensure the project compiles successfully for both Windows (`GOOS=windows go build`) and Unix platforms.
- **Testing:** Verify that the sleep logic functions correctly without crashing the agent. EDR evasion is theoretically sound based on the indirect syscall mechanism.
