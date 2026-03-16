package commands

import (
	"os"
	"strings"
	"testing"

	"killa/pkg/structs"
)

func TestEnvCommandName(t *testing.T) {
	cmd := &EnvCommand{}
	if cmd.Name() != "env" {
		t.Errorf("expected 'env', got %q", cmd.Name())
	}
}

func TestEnvListAll(t *testing.T) {
	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = ""
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	// Should contain at least PATH
	if !strings.Contains(result.Output, "PATH=") {
		t.Error("env output should contain PATH")
	}
}

func TestEnvFilter(t *testing.T) {
	os.Setenv("KILLA_TEST_VAR", "test_value")
	defer os.Unsetenv("KILLA_TEST_VAR")

	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = "KILLA_TEST"
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "KILLA_TEST_VAR=test_value") {
		t.Errorf("output should contain filtered var, got %q", result.Output)
	}
}

func TestEnvFilterCaseInsensitive(t *testing.T) {
	os.Setenv("KILLA_CASE_TEST", "val")
	defer os.Unsetenv("KILLA_CASE_TEST")

	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = "killa_case"
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "KILLA_CASE_TEST") {
		t.Error("filter should be case-insensitive")
	}
}

func TestEnvFilterNoMatch(t *testing.T) {
	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = "ZZZZNONEXISTENT999"
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "No environment variables") {
		t.Error("should report no matching vars")
	}
}

func TestEnvSorted(t *testing.T) {
	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = ""
	result := cmd.Execute(task)
	lines := strings.Split(result.Output, "\n")
	for i := 1; i < len(lines); i++ {
		if lines[i] < lines[i-1] {
			t.Error("env output should be sorted")
			break
		}
	}
}
