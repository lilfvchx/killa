+++
title = "ptrace-inject"
chapter = false
weight = 112
hidden = false
+++

## Summary

Linux process injection via the ptrace syscall. Attaches to a target process, writes shellcode into an executable memory region, redirects execution, and optionally restores the original code and registers after completion. Includes a configuration check mode that reports ptrace scope, capabilities, and candidate processes.

{{% notice info %}}Linux Only (x86_64){{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `check`: report ptrace config and candidate processes. `inject`: perform shellcode injection. |
| pid | Inject | Target process ID to inject into |
| filename | Inject (UI) | Select shellcode file from Mythic's file storage |
| file | Inject (UI) | Upload a new shellcode file |
| shellcode_b64 | Inject (CLI) | Base64-encoded shellcode (for API/CLI usage) |
| restore | No | Restore original code and registers after execution (default: true) |
| timeout | No | Timeout in seconds waiting for shellcode completion (default: 30) |

## Usage

```
# Check ptrace configuration, capabilities, and candidate processes
ptrace-inject -action check

# Inject shellcode from Mythic file storage into a target process
ptrace-inject -action inject -pid 1234 -filename shellcode.bin

# Inject with upload (via Mythic UI)
ptrace-inject -action inject -pid 1234 -file <upload>

# Fire-and-forget injection (no restore)
ptrace-inject -action inject -pid 1234 -filename shellcode.bin -restore false

# Custom timeout
ptrace-inject -action inject -pid 1234 -filename shellcode.bin -timeout 60
```

## Injection Process

1. **PTRACE_ATTACH** â€” Attach to the target process (sends SIGSTOP)
2. **PTRACE_GETREGS** â€” Save the original register state (RIP, RSP, etc.)
3. **Find executable region** â€” Parse `/proc/<pid>/maps` for an r-xp memory region (skips vdso/vsyscall)
4. **PTRACE_PEEKTEXT** â€” Backup the original code at the injection point
5. **PTRACE_POKETEXT** â€” Write shellcode (with appended INT3 if restore=true)
6. **PTRACE_SETREGS** â€” Set RIP to the shellcode address
7. **PTRACE_CONT** â€” Resume execution at the shellcode
8. **Wait for SIGTRAP** â€” Poll with timeout for the INT3 breakpoint
9. **PTRACE_POKETEXT** â€” Restore original code (if restore=true)
10. **PTRACE_SETREGS** â€” Restore original registers (if restore=true)
11. **PTRACE_DETACH** â€” Detach from the process

## Check Output

The `check` action reports:
- **ptrace_scope** â€” Yama LSM setting (0=classic, 1=restricted, 2=admin-only, 3=disabled)
- **Current UID/EUID** â€” Process identity
- **Capabilities** â€” CapInh, CapPrm, CapEff, CapBnd, CapAmb
- **Candidate Processes** â€” Same-UID processes available for injection (up to 20)

## OPSEC Considerations

- **ptrace_scope** controls who can attach:
  - `0` (classic): Any same-UID process can ptrace â€” injection works freely
  - `1` (restricted): Only parent can ptrace child â€” must be a child process of the agent
  - `2` (admin-only): Requires `CAP_SYS_PTRACE` capability
  - `3` (disabled): No ptrace allowed at all
- Root (EUID 0) bypasses ptrace_scope restrictions
- `check` action only reads from `/proc` â€” no subprocess execution
- `inject` action uses only ptrace syscalls â€” no external binary invocation
- Shellcode execution is in the context of the target process (PID, UID, capabilities)
- If `restore=true`, the target process resumes normal execution after injection â€” minimal forensic footprint
- If `restore=false`, the process is permanently modified â€” original code at the injection point is lost
- On failure at any step, cleanup is attempted (restore code + registers + detach)
- x86_64 architecture only (uses `PTRACE_GETREGS`/`PTRACE_SETREGS` with `PtraceRegs`)

## MITRE ATT&CK Mapping

- **T1055.008** â€” Process Injection: Ptrace System Calls
