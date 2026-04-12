# Iteration Context: Process Hollowing using Section Objects (NtCreateSection)

## Context
Process Hollowing via standard Windows APIs (VirtualAllocEx, WriteProcessMemory, ResumeThread) is widely signatured. While the agent supports basic hollowing, using Sections provides a stealthier, lower-level primitive for injecting code by mapping sections across process boundaries.

## Technique
We will implement "Section Mapping Injection" (a primitive often used in phantom/doppelganger techniques) via indirect syscalls `NtCreateSection`, `NtMapViewOfSection`, and `NtUnmapViewOfSection`. The memory is created as a Section and mapped into the target, which avoids the classic `VirtualAllocEx` / `WriteProcessMemory` API sequence.

## Justification
Section-based injection maps a view of memory into a remote process. This memory doesn't trigger the same allocations callbacks as standard memory operations, providing better evasion against EDRs that closely monitor private memory allocation for process injection.

## Implementation Details
1. Add `NtCreateSection`, `NtMapViewOfSection`, and `NtUnmapViewOfSection` indirect syscall wrappers in `pkg/commands/indirect_syscalls_windows.go`.
2. Add these functions to the `keyFunctions` slice to ensure their syscall stubs are generated dynamically.
3. We will modify `pkg/commands/hollow_windows.go` (if it exists) or create `pkg/commands/section_inject_windows.go` to provide a new injection mechanism using these new indirect syscalls.

## Validation
A process should be spawned and code should execute inside it by creating a section, mapping a view into the current process to write the shellcode, mapping a view into the target process as RX, and creating a thread pointing to the section map.
