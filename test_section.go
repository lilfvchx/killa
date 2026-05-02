package main

import (
    "fmt"
    "syscall"
    "unsafe"
    "golang.org/x/sys/windows"
)

func main() {
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    fmt.Printf("ntdll.dll address: %v\n", ntdll)
    procNtCreateSection := ntdll.NewProc("NtCreateSection")
    fmt.Printf("NtCreateSection address: %v\n", procNtCreateSection)
    procNtMapViewOfSection := ntdll.NewProc("NtMapViewOfSection")
    fmt.Printf("NtMapViewOfSection address: %v\n", procNtMapViewOfSection)
}
