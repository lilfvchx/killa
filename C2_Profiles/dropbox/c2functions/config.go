package c2functions

import (
	"encoding/json"
	"fmt"
	"os"

	c2structs "github.com/MythicMeta/MythicContainer/c2_structs"
)

const dropboxServerConfigPath = "./dropbox_server_config.json"

type dropboxServerConfig struct {
	Token         string `json:"token"`
	TaskFolder    string `json:"task_folder"`
	ResultFolder  string `json:"result_folder"`
	ArchiveFolder string `json:"archive_folder"`
	PollInterval  int    `json:"poll_interval"`
}

func configCheck(message c2structs.C2ConfigCheckMessage) c2structs.C2ConfigCheckMessageResponse {
	cfg := dropboxServerConfig{}

	token, err := message.GetStringArg("dropbox_token")
	if err != nil || token == "" {
		return c2structs.C2ConfigCheckMessageResponse{
			Success: false,
			Error:   "dropbox_token is required",
		}
	}
	taskFolder, err := message.GetStringArg("dropbox_task_folder")
	if err != nil || taskFolder == "" {
		taskFolder = "/killa/tasks"
	}
	resultFolder, err := message.GetStringArg("dropbox_result_folder")
	if err != nil || resultFolder == "" {
		resultFolder = "/killa/results"
	}
	archiveFolder, err := message.GetStringArg("dropbox_archive_folder")
	if err != nil {
		archiveFolder = ""
	}
	pollInterval, err := message.GetNumberArg("dropbox_poll_interval")
	if err != nil || int(pollInterval) <= 0 {
		pollInterval = 5
	}

	cfg.Token = token
	cfg.TaskFolder = taskFolder
	cfg.ResultFolder = resultFolder
	cfg.ArchiveFolder = archiveFolder
	cfg.PollInterval = int(pollInterval)

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return c2structs.C2ConfigCheckMessageResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to marshal dropbox server config: %v", err),
		}
	}
	tmpPath := dropboxServerConfigPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return c2structs.C2ConfigCheckMessageResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to write dropbox server config: %v", err),
		}
	}
	if err := os.Rename(tmpPath, dropboxServerConfigPath); err != nil {
		return c2structs.C2ConfigCheckMessageResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to activate dropbox server config: %v", err),
		}
	}

	return c2structs.C2ConfigCheckMessageResponse{
		Success:               true,
		Message:               "Dropbox server configuration saved",
		RestartInternalServer: true,
	}
}
