package c2functions

import (
	"encoding/json"
	"fmt"
	"os"

	c2structs "github.com/MythicMeta/MythicContainer/c2_structs"
)

const discordServerConfigPath = "./discord_server_config.json"

type discordServerConfig struct {
	BotToken     string `json:"bot_token"`
	ChannelID    string `json:"channel_id"`
	PollInterval int    `json:"poll_interval"`
}

func configCheck(message c2structs.C2ConfigCheckMessage) c2structs.C2ConfigCheckMessageResponse {
	cfg := discordServerConfig{}

	botToken, err := message.GetStringArg("discord_bot_token")
	if err != nil || botToken == "" {
		return c2structs.C2ConfigCheckMessageResponse{
			Success: false,
			Error:   "discord_bot_token is required",
		}
	}
	channelID, err := message.GetStringArg("discord_channel_id")
	if err != nil || channelID == "" {
		return c2structs.C2ConfigCheckMessageResponse{
			Success: false,
			Error:   "discord_channel_id is required",
		}
	}
	pollInterval, err := message.GetNumberArg("discord_poll_interval")
	if err != nil || int(pollInterval) <= 0 {
		pollInterval = 5
	}

	cfg.BotToken = botToken
	cfg.ChannelID = channelID
	cfg.PollInterval = int(pollInterval)

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return c2structs.C2ConfigCheckMessageResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to marshal discord server config: %v", err),
		}
	}
	tmpPath := discordServerConfigPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return c2structs.C2ConfigCheckMessageResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to write discord server config: %v", err),
		}
	}
	if err := os.Rename(tmpPath, discordServerConfigPath); err != nil {
		return c2structs.C2ConfigCheckMessageResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to activate discord server config: %v", err),
		}
	}

	return c2structs.C2ConfigCheckMessageResponse{
		Success:               true,
		Message:               "Discord server configuration saved",
		RestartInternalServer: true,
	}
}
