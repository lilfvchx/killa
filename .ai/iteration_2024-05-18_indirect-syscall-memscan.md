# Iteration: mem_scan using Indirect Syscalls

## Context
The `mem_scan` command is designed to search through an active process memory for specific byte sequences. It previously used `VirtualQueryEx` and `ReadProcessMemory` Win32 APIs exported from `kernel32.dll`. Relying on standard API calls leaves the agent vulnerable to EDR/AV user-mode API hooking, potentially exposing the scanning activity or causing it to be blocked.

## Technique
We implemented indirect syscall wrappers for `NtQueryVirtualMemory` and `NtReadVirtualMemory` using the existing `SyscallResolver` mechanism in `indirect_syscalls_windows.go`. We then modified `mem_scan_windows.go` to use these indirect syscalls (if available via `IndirectSyscallsAvailable()`) instead of the standard Win32 API calls. This forces the execution flow to jump directly into the `syscall; ret` gadget inside `ntdll.dll`, effectively bypassing any inline hooks placed by defensive solutions on either `kernel32.dll` or `ntdll.dll` function prologues.

## Reasoning
Using indirect syscalls minimizes the agent's architectural footprint. Memory scanning operations are inherently noisy since they require querying memory regions and reading chunk by chunk. By avoiding standard userland hooks during these repeated actions, the activity becomes significantly stealthier. It helps ensure a "clean" execution environment less prone to telemetry generation while maintaining robust functionality.

## Changes
- `Payload_Type/killa/killa/agent_code/pkg/commands/indirect_syscalls_windows.go`:
  - Added `NtQueryVirtualMemory` to the `keyFunctions` list resolved at initialization.
  - Implemented the wrapper function `IndirectNtQueryVirtualMemory`.
- `Payload_Type/killa/killa/agent_code/pkg/commands/mem_scan_windows.go`:
  - Updated `scanProcessMemory` to check `IndirectSyscallsAvailable()` and invoke `IndirectNtQueryVirtualMemory` instead of `procVirtualQueryExMS.Call`.
  - Updated the memory reading loop to use `IndirectNtReadVirtualMemory` rather than `procReadProcessMemoryMS.Call`.
- Fixed several struct and variable duplication issues in the `net*` commands that prevented the Windows build from succeeding.

## Validation
- Verified compilation of Windows target via `GOOS=windows go build`.
- Verified compilation of tests via `GOOS=windows go test -c`.
