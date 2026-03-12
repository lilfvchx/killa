package main

import (
	killaAgent "killa/killa/agentfunctions"

	"github.com/MythicMeta/MythicContainer"
)

func main() {
	// Load agent function definitions (init() functions in agentfunctions/)
	killaAgent.Initialize()

	// Sync definitions with Mythic and listen for build/task requests
	MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{
		MythicContainer.MythicServiceC2,
		MythicContainer.MythicServicePayload,
	})
}
