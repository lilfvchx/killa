# Iteration: Section Mapping Injection

**Context:**
Classic remote process injection relies heavily on `VirtualAllocEx` and `WriteProcessMemory`. These Win32 APIs are extremely well-signatured by EDR (Endpoint Detection and Response) systems. They monitor for `NtAllocateVirtualMemory` and `NtWriteVirtualMemory` cross-process calls, easily flagging the behavior as malicious.

**Technique / Primitive:**
To bypass this, we implemented "Section Mapping Injection" utilizing the Windows Memory Manager. Instead of allocating and writing memory directly into the remote process, we:
1. Create a memory section object backed by the paging file using `NtCreateSection` (`PAGE_EXECUTE_READWRITE`).
2. Map a view of that section into our local process using `NtMapViewOfSection` (`PAGE_READWRITE`).
3. Copy the shellcode into our local view.
4. Map a view of the same section into the remote target process using `NtMapViewOfSection` (`PAGE_EXECUTE_READ`).
5. Execute it using `NtCreateThreadEx`.

**Rationale:**
By using `NtCreateSection` and `NtMapViewOfSection`, we avoid the highly-monitored `NtAllocateVirtualMemory` and `NtWriteVirtualMemory` APIs. The section mapping mechanism is a legitimate part of the OS memory sharing design (e.g., used by DLL loading and inter-process communication), making it harder for heuristics to definitively classify the action as malicious injection without generating false positives. Additionally, we enforce W^X by mapping the local view as RW and the remote view as RX, avoiding any RWX pages. All calls are made via indirect syscalls (resolving stubs from ntdll) to bypass user-mode API hooking entirely.

**Code Changes:**
- Added `NtCreateSection`, `NtMapViewOfSection`, and `NtUnmapViewOfSection` to `keyFunctions` in `indirect_syscalls_windows.go`.
- Implemented `IndirectNtCreateSection`, `IndirectNtMapViewOfSection`, and `IndirectNtUnmapViewOfSection` in `indirect_syscalls_windows.go` (converting pointers safely within `syscall.SyscallN`).
- Added `SectionInjectionCommand` in `section_injection_windows.go`.
- Registered `SectionInjectionCommand` in `registry_windows.go`.
- Added Mythic UI integration in `agentfunctions/section_injection.go`.

**Validation:**
- Validate the logic compiles via `go build` for both Windows agent code and the Mythic container.
- Verification in a lab environment: Use API Monitor / Sysmon to confirm `VirtualAllocEx` and `WriteProcessMemory` are not called. Ensure shellcode executes successfully in a remote PID (e.g., spawning calculator or reverse shell).
