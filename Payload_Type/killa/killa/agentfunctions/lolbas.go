package agentfunctions

import (
	"encoding/json"
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("killa").AddCommand(agentstructs.Command{
		Name:                "lolbas",
		Description:         "Execute commands/payloads via common Windows LOLBAS templates",
		HelpString:          "lolbas -action list | lolbas -action exec -binary <name> [-target <value>] [-args <value>] [-command <value>]",
		Version:             1,
		MitreAttackMappings: []string{"T1218"},
		SupportedUIFeatures: []string{},
		Author:              "@codex",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                      "action",
				CLIName:                   "action",
				ModalDisplayName:          "Action",
				ParameterType:             agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:                   []string{"list", "exec"},
				DefaultValue:              "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{{ParameterIsRequired: true, GroupName: "Default"}},
			},
			{
				Name:                      "binary",
				CLIName:                   "binary",
				ModalDisplayName:          "LOLBAS Binary",
				ParameterType:             agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:                   []string{"mshta", "regsvr32", "rundll32", "certutil", "msiexec", "forfiles", "wmic"},
				DefaultValue:              "mshta",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{{ParameterIsRequired: false, GroupName: "Default"}},
			},
			{
				Name:                      "target",
				CLIName:                   "target",
				ModalDisplayName:          "Target",
				ParameterType:             agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{{ParameterIsRequired: false, GroupName: "Default"}},
			},
			{
				Name:                      "args",
				CLIName:                   "args",
				ModalDisplayName:          "Additional Args",
				ParameterType:             agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{{ParameterIsRequired: false, GroupName: "Default"}},
			},
			{
				Name:                      "command",
				CLIName:                   "command",
				ModalDisplayName:          "Command",
				ParameterType:             agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{{ParameterIsRequired: false, GroupName: "Default"}},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			input = strings.TrimSpace(input)
			if strings.HasPrefix(input, "{") {
				var v map[string]any
				if err := json.Unmarshal([]byte(input), &v); err == nil {
					b, _ := json.Marshal(v)
					args.SetManualArgs(string(b))
					return nil
				}
			}
			if strings.EqualFold(input, "list") {
				args.SetManualArgs(`{"action":"list"}`)
				return nil
			}
			if strings.HasPrefix(strings.ToLower(input), "raw:") {
				args.SetManualArgs(input)
				return nil
			}
			return fmt.Errorf("invalid input, use JSON, 'list', or raw:<command>")
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			b, err := json.Marshal(input)
			if err != nil {
				return err
			}
			args.SetManualArgs(string(b))
			return nil
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: task.Task.ID}
			if displayParams, err := task.Args.GetFinalArgs(); err == nil {
				response.DisplayParams = &displayParams
				createArtifact(task.Task.ID, "Process Create", displayParams)
			}
			return response
		},
	})
}
