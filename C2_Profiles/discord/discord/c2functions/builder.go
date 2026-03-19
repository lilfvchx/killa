package c2functions

import (
	c2structs "github.com/MythicMeta/MythicContainer/c2_structs"
)

var discordC2Definition = c2structs.C2Profile{
	Name:           "discord",
	Author:         "@galoryber",
	Description:    "Discord channel/DM transport for tasking and responses.",
	IsP2p:          false,
	IsServerRouted: true,
}

var discordC2Parameters = []c2structs.C2Parameter{
	{
		Name:          "discord_bot_token",
		Description:   "Discord bot OAuth token (xoxb-...).",
		DefaultValue:  "",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      true,
	},
	{
		Name:          "discord_channel_id",
		Description:   "Discord channel or direct-message conversation ID.",
		DefaultValue:  "",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      true,
	},
	{
		Name:          "discord_poll_interval",
		Description:   "Polling interval in seconds for checking inbound messages.",
		DefaultValue:  5,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      false,
		VerifierRegex: "^[0-9]+$",
	},
	{
		Name:          "callback_interval",
		Description:   "Base sleep interval in seconds.",
		DefaultValue:  "10",
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      false,
		VerifierRegex: "^[0-9]+$",
	},
	{
		Name:          "callback_jitter",
		Description:   "Sleep jitter percentage (0-100).",
		DefaultValue:  "10",
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
		DefaultValue:  "365",
		ParameterType: c2structs.C2_PARAMETER_TYPE_DATE,
		Required:      false,
	},
}

func Initialize() {
	c2structs.AllC2Data.Get("discord").AddC2Definition(discordC2Definition)
	c2structs.AllC2Data.Get("discord").AddParameters(discordC2Parameters)
}
