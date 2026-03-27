package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
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
	mu sync.Mutex
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

	mythicHost := os.Getenv("MYTHIC_SERVER_HOST")
	if mythicHost == "" {
		mythicHost = "127.0.0.1"
	}
	mythicPort := os.Getenv("MYTHIC_SERVER_PORT")
	if mythicPort == "" {
		mythicPort = "17443"
	}
	url := fmt.Sprintf("http://%s:%s/api/v1.4/agent_message", mythicHost, mythicPort)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(decoded))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("mythic", "dropbox")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mythic returned status code %d", resp.StatusCode)
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if len(responseBody) == 0 {
		return "", nil
	}

	return encryptEnvelope(env.UUID, "dropbox", responseBody)
}

func (s *dropboxService) uploadText(remotePath, content string) error {
	req, err := http.NewRequest("POST", dropboxContent+"/files/upload", strings.NewReader(content))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Dropbox-API-Arg", fmt.Sprintf(`{"path":"%s","mode":"overwrite","autorename":false,"mute":true}`, remotePath))
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
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
