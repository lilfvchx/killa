package profiles

import (
	"killa/pkg/dropbox"
	"killa/pkg/http"
	"killa/pkg/slack"
	"killa/pkg/structs"
	"killa/pkg/tcp"
)

// Profile interface defines the C2 profile methods
type Profile interface {
	Checkin(agent *structs.Agent) error
	GetTasking(agent *structs.Agent, outboundSocks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error)
	PostResponse(response structs.Response, agent *structs.Agent, socks []structs.SocksMsg) ([]byte, error)
	GetCallbackUUID() string
}

// NewProfile creates a new profile based on the HTTP profile
func NewProfile(httpProfile *http.HTTPProfile) Profile {
	return httpProfile
}

// NewTCPProfile creates a new profile based on the TCP P2P profile
func NewTCPProfile(tcpProfile *tcp.TCPProfile) Profile {
	return tcpProfile
}

// NewSlackProfile creates a new profile based on Slack transport.
func NewSlackProfile(slackProfile *slack.SlackProfile) Profile {
	return slackProfile
}

// NewDropboxProfile creates a new profile based on Dropbox transport.
func NewDropboxProfile(dropboxProfile *dropbox.DropboxProfile) Profile {
	return dropboxProfile
}
