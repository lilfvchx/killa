package commands

import (
	"strings"
	"testing"

	"killa/pkg/structs"
)

func TestLolbasList(t *testing.T) {
	cmd := &LolbasCommand{}
	res := cmd.Execute(structs.Task{Params: `{"action":"list"}`})
	if res.Status != "success" {
		t.Fatalf("expected success, got %s: %s", res.Status, res.Output)
	}
	if !strings.Contains(res.Output, "mshta") || !strings.Contains(res.Output, "wmic") {
		t.Fatalf("unexpected list output: %s", res.Output)
	}
}

func TestLolbasValidation(t *testing.T) {
	cmd := &LolbasCommand{}
	res := cmd.Execute(structs.Task{Params: `{"action":"exec"}`})
	if res.Status != "error" || !strings.Contains(strings.ToLower(res.Output), "binary") {
		t.Fatalf("expected binary validation error, got: %s / %s", res.Status, res.Output)
	}
}
