package c2functions

import (
	c2structs "github.com/MythicMeta/MythicContainer/c2_structs"
)

var dropboxC2Definition = c2structs.C2Profile{
	Name:           "dropbox",
	Author:         "@galoryber",
	Description:    "Dropbox file-based transport for tasking and responses.",
	IsP2p:          false,
	IsServerRouted: true,
}

var dropboxC2Parameters = []c2structs.C2Parameter{
	{
		Name:          "dropbox_token",
		Description:   "Dropbox OAuth access token.",
		DefaultValue:  "",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      true,
	},
	{
		Name:          "dropbox_task_folder",
		Description:   "Folder to read instruction files from.",
		DefaultValue:  "/killa/tasks",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      false,
	},
	{
		Name:          "dropbox_result_folder",
		Description:   "Folder to write outbound result files to.",
		DefaultValue:  "/killa/results",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      false,
	},
	{
		Name:          "dropbox_archive_folder",
		Description:   "Optional folder for processed inbound files. Empty means delete after processing.",
		DefaultValue:  "",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      false,
	},
	{
		Name:          "dropbox_poll_interval",
		Description:   "Polling interval in seconds for checking inbound files.",
		DefaultValue:  5,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      false,
		VerifierRegex: "^[0-9]+$",
	},
	{
		Name:          "callback_interval",
		Description:   "Base sleep interval in seconds.",
		DefaultValue:  10,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      false,
		VerifierRegex: "^[0-9]+$",
	},
	{
		Name:          "callback_jitter",
		Description:   "Sleep jitter percentage (0-100).",
		DefaultValue:  10,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      false,
		VerifierRegex: "^[0-9]+$",
	},
	{
		Name:          "AESPSK",
		Description:   "Encryption Type",
		DefaultValue:  "aes256_hmac",
		ParameterType: c2structs.C2_PARAMETER_TYPE_CHOOSE_ONE,
		Required:      false,
		IsCryptoType:  true,
		Choices: []string{
			"aes256_hmac",
			"none",
		},
	},
	{
		Name:          "killdate",
		Description:   "Kill Date",
		DefaultValue:  365,
		ParameterType: c2structs.C2_PARAMETER_TYPE_DATE,
		Required:      false,
	},
}

func Initialize() {
	c2structs.AllC2Data.Get("dropbox").AddC2Definition(dropboxC2Definition)
	c2structs.AllC2Data.Get("dropbox").AddParameters(dropboxC2Parameters)
}
