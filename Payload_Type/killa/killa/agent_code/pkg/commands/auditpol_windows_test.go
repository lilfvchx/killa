//go:build windows
// +build windows

package commands

import (
	"testing"

	"killa/pkg/structs"
)

func TestAuditPolCommandName(t *testing.T) {
	cmd := &AuditPolCommand{}
	if cmd.Name() != "auditpol" {
		t.Errorf("expected 'auditpol', got '%s'", cmd.Name())
	}
}

func TestAuditPolCommandDescription(t *testing.T) {
	cmd := &AuditPolCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestAuditSettingString(t *testing.T) {
	cases := []struct {
		setting  uint32
		expected string
	}{
		{auditPolicyNone, "No Auditing"},
		{auditPolicySuccess, "Success"},
		{auditPolicyFailure, "Failure"},
		{auditPolicySuccessFailure, "Success and Failure"},
		{0xFF, "Unknown (0xFF)"}, // default case
	}

	for _, c := range cases {
		result := auditSettingString(c.setting)
		if result != c.expected {
			t.Errorf("expected %s, got %s for setting 0x%X", c.expected, result, c.setting)
		}
	}
}

func TestMatchSubcategories(t *testing.T) {
	// Test "all"
	allMatches := matchSubcategories("all")
	if len(allMatches) != len(auditSubcategories) {
		t.Errorf("expected %d matches for 'all', got %d", len(auditSubcategories), len(allMatches))
	}

	// Test specific category
	logonLogoffMatches := matchSubcategories("Logon/Logoff")
	if len(logonLogoffMatches) != 3 { // Logon, Logoff, Special Logon
		t.Errorf("expected 3 matches for 'Logon/Logoff', got %d", len(logonLogoffMatches))
	}

	// Test specific subcategory
	processCreationMatches := matchSubcategories("Process Creation")
	if len(processCreationMatches) != 1 {
		t.Errorf("expected 1 match for 'Process Creation', got %d", len(processCreationMatches))
	} else if processCreationMatches[0].Name != "Process Creation" {
		t.Errorf("expected match to be 'Process Creation', got %s", processCreationMatches[0].Name)
	}

	// Test partial match (case insensitive)
	sysMatches := matchSubcategories("sys")
	if len(sysMatches) == 0 {
		t.Errorf("expected multiple matches for 'sys', got 0")
	}

	// Test non-existent category
	noneMatches := matchSubcategories("NonExistentCategory123")
	if len(noneMatches) != 0 {
		t.Errorf("expected 0 matches for 'NonExistentCategory123', got %d", len(noneMatches))
	}
}

func TestAuditPolExecute_ParseError(t *testing.T) {
	cmd := &AuditPolCommand{}
	task := structs.Task{
		Params: `{invalid_json}`,
	}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status for invalid JSON, got %s", result.Status)
	}
}

func TestAuditPolExecute_UnknownAction(t *testing.T) {
	cmd := &AuditPolCommand{}
	task := structs.Task{
		Params: `{"action": "fake_action"}`,
	}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status for unknown action, got %s", result.Status)
	}
}

func TestAuditPolExecute_DisableEnableRequiresCategory(t *testing.T) {
	cmd := &AuditPolCommand{}

	// Test disable without category
	taskDisable := structs.Task{
		Params: `{"action": "disable"}`,
	}
	resultDisable := cmd.Execute(taskDisable)
	if resultDisable.Status != "error" {
		t.Errorf("expected error status for disable without category, got %s", resultDisable.Status)
	}

	// Test enable without category
	taskEnable := structs.Task{
		Params: `{"action": "enable"}`,
	}
	resultEnable := cmd.Execute(taskEnable)
	if resultEnable.Status != "error" {
		t.Errorf("expected error status for enable without category, got %s", resultEnable.Status)
	}
}

func TestAuditPolExecute_DisableEnableNoMatch(t *testing.T) {
	cmd := &AuditPolCommand{}

	// Test disable with non-existent category
	taskDisable := structs.Task{
		Params: `{"action": "disable", "category": "NonExistentCategory123"}`,
	}
	resultDisable := cmd.Execute(taskDisable)
	if resultDisable.Status != "error" {
		t.Errorf("expected error status for disable with non-existent category, got %s", resultDisable.Status)
	}

	// Test enable with non-existent category
	taskEnable := structs.Task{
		Params: `{"action": "enable", "category": "NonExistentCategory123"}`,
	}
	resultEnable := cmd.Execute(taskEnable)
	if resultEnable.Status != "error" {
		t.Errorf("expected error status for enable with non-existent category, got %s", resultEnable.Status)
	}
}
