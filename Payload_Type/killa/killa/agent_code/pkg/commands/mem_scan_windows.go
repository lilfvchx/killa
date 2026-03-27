//go:build windows

package commands

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	msMemCommit        = 0x1000
	msPageNoAccess     = 0x01
	msPageGuard        = 0x100
	msChunkSize        = 4 * 1024 * 1024 // 4 MB read chunks
	msProcessVMRead    = 0x0010
	msProcessQueryInfo = 0x0400
)

// MEMORY_BASIC_INFORMATION for VirtualQueryEx (64-bit layout, 48 bytes)
type memoryBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	pad1              uint32 // alignment padding after DWORD
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	pad2              uint32 // struct tail padding
}

var (
	// Use unique names to avoid collision with other command files
	procVirtualQueryExMS    = kernel32.NewProc("VirtualQueryEx")
	procReadProcessMemoryMS = kernel32.NewProc("ReadProcessMemory")
)

func scanProcessMemory(pid int, searchBytes []byte, maxResults int, contextBytes int) ([]memScanMatch, int, uint64, error) {
	// Open target process
	access := uint32(msProcessVMRead | msProcessQueryInfo)
	handle, err := windows.OpenProcess(access, false, uint32(pid))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("OpenProcess(%d): %v", pid, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	var matches []memScanMatch
	var regionsScanned int
	var bytesScanned uint64

	var addr uintptr
	var mbi memoryBasicInfo
	mbiSize := unsafe.Sizeof(mbi)

	for len(matches) < maxResults {
		// Query next memory region using indirect syscalls if available
		var ret uint32
		if IndirectSyscallsAvailable() {
			var returnLength uintptr
			// MemoryBasicInformation is class 0
			status := IndirectNtQueryVirtualMemory(
				uintptr(handle),
				addr,
				0, // MemoryBasicInformation
				uintptr(unsafe.Pointer(&mbi)),
				mbiSize,
				&returnLength,
			)
			if status == 0 { // STATUS_SUCCESS
				ret = 1 // simulate VirtualQueryEx success
			} else {
				ret = 0
			}
		} else {
			r, _, _ := procVirtualQueryExMS.Call(
				uintptr(handle),
				addr,
				uintptr(unsafe.Pointer(&mbi)),
				mbiSize,
			)
			ret = uint32(r)
		}

		if ret == 0 {
			break // No more regions
		}

		// Advance to next region
		nextAddr := mbi.BaseAddress + mbi.RegionSize
		if nextAddr <= addr {
			break // Overflow protection
		}
		addr = nextAddr

		// Skip non-committed, guarded, or no-access regions
		if mbi.State != msMemCommit {
			continue
		}
		if mbi.Protect == msPageNoAccess || mbi.Protect&msPageGuard != 0 {
			continue
		}

		// Skip very large regions (>256 MB) to avoid hanging
		if mbi.RegionSize > 256*1024*1024 {
			continue
		}

		regionsScanned++

		// Read region in chunks to handle large regions
		regionBase := mbi.BaseAddress
		remaining := mbi.RegionSize

		for remaining > 0 && len(matches) < maxResults {
			chunkSize := remaining
			if chunkSize > msChunkSize {
				chunkSize = msChunkSize
			}

			buf := make([]byte, chunkSize)
			var bytesRead uintptr

			var readRet uint32
			if IndirectSyscallsAvailable() {
				status := IndirectNtReadVirtualMemory(
					uintptr(handle),
					regionBase+(mbi.RegionSize-remaining),
					uintptr(unsafe.Pointer(&buf[0])),
					chunkSize,
					&bytesRead,
				)
				if status == 0 { // STATUS_SUCCESS
					readRet = 1
				} else {
					readRet = 0
				}
			} else {
				r, _, _ := procReadProcessMemoryMS.Call(
					uintptr(handle),
					regionBase+(mbi.RegionSize-remaining),
					uintptr(unsafe.Pointer(&buf[0])),
					chunkSize,
					uintptr(unsafe.Pointer(&bytesRead)),
				)
				readRet = uint32(r)
			}

			if readRet == 0 || bytesRead == 0 {
				break // Can't read this chunk
			}

			readOffset := mbi.RegionSize - remaining
			bytesScanned += uint64(bytesRead)
			matches = searchInRegion(buf[:bytesRead], uint64(regionBase+readOffset), searchBytes, contextBytes, maxResults, matches)

			remaining -= chunkSize
		}
	}

	return matches, regionsScanned, bytesScanned, nil
}
