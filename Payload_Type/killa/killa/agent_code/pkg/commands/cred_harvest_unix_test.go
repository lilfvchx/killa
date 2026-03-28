//go:build !windows

package commands

import (
	"os"
	"strings"
	"testing"
)

// mockOSReadFile returns a function that implements os.ReadFile for testing.
// It uses a map of filenames to contents.
func mockOSReadFile(files map[string]string) func(string) ([]byte, error) {
	return func(filename string) ([]byte, error) {
		if content, ok := files[filename]; ok {
			return []byte(content), nil
		}
		return nil, &os.PathError{Op: "open", Path: filename, Err: os.ErrNotExist}
	}
}

// setMockOSReadFile overrides the package-level osReadFile and returns a cleanup function
func setMockOSReadFile(t *testing.T, files map[string]string) {
	orig := osReadFile
	osReadFile = mockOSReadFile(files)
	t.Cleanup(func() {
		osReadFile = orig
	})
}

func TestCredShadow_Success(t *testing.T) {
	mockFiles := map[string]string{
		"/etc/shadow":   "root:$6$xyz...:18000:0:99999:7:::\nuser1:$1$abc...:18000:0:99999:7:::\nnobody:*:18000:0:99999:7:::\nlocked:!$6$def...:18000:0:99999:7:::\n",
		"/etc/passwd":   "root:x:0:0:root:/root:/bin/bash\nuser1:x:1000:1000:User:/home/user1:/bin/bash\nlegacy:oldhash:1001:1001:Legacy:/home/legacy:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
		"/etc/gshadow":  "root:*::\nadmin:$6$ghighigh::user1\n",
	}

	setMockOSReadFile(t, mockFiles)

	args := credHarvestArgs{Action: "shadow"}
	result := credShadow(args)

	if result.Status != "success" {
		t.Fatalf("expected status 'success', got '%s'", result.Status)
	}
	if !result.Completed {
		t.Errorf("expected Completed to be true")
	}

	// Assert output contains expected data
	output := result.Output
	if !strings.Contains(output, "root:$6$xyz...") {
		t.Errorf("expected output to contain root hash")
	}
	if !strings.Contains(output, "user1:$1$abc...") {
		t.Errorf("expected output to contain user1 hash")
	}
	if strings.Contains(output, "nobody:*") {
		t.Errorf("expected output to NOT contain locked nobody account")
	}
	if strings.Contains(output, "locked:!") {
		t.Errorf("expected output to NOT contain locked 'locked' account")
	}

	if !strings.Contains(output, "WARNING: Password hash in /etc/passwd: oldhash") {
		t.Errorf("expected output to warn about legacy hash in /etc/passwd")
	}
	if !strings.Contains(output, "admin:$6$ghighigh::user1") {
		t.Errorf("expected output to contain admin group hash")
	}

	// Assert Mythic credentials
	if result.Credentials == nil {
		t.Fatalf("expected credentials to be reported")
	}
	creds := *result.Credentials
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials reported from shadow, got %d", len(creds))
	}

	foundRoot := false
	foundUser1 := false
	for _, c := range creds {
		if c.Account == "root" && c.Credential == "$6$xyz..." {
			foundRoot = true
		}
		if c.Account == "user1" && c.Credential == "$1$abc..." {
			foundUser1 = true
		}
	}
	if !foundRoot || !foundUser1 {
		t.Errorf("expected root and user1 credentials to be reported")
	}
}

func TestCredShadow_WithFilterUser(t *testing.T) {
	mockFiles := map[string]string{
		"/etc/shadow":   "root:$6$xyz...:18000:0:99999:7:::\nuser1:$1$abc...:18000:0:99999:7:::\n",
		"/etc/passwd":   "root:x:0:0:root:/root:/bin/bash\nuser1:x:1000:1000:User:/home/user1:/bin/bash\n",
		"/etc/gshadow":  "root:*::\n",
	}

	setMockOSReadFile(t, mockFiles)

	args := credHarvestArgs{Action: "shadow", User: "USER1"}
	result := credShadow(args)

	if !strings.Contains(result.Output, "user1:$1$abc...") {
		t.Errorf("expected output to contain user1 hash")
	}
	if strings.Contains(result.Output, "root:$6$xyz...") {
		t.Errorf("expected output to NOT contain root hash due to filter")
	}

	if !strings.Contains(result.Output, "user1 (uid=1000") {
		t.Errorf("expected output to contain user1 passwd info")
	}
	if strings.Contains(result.Output, "root (uid=0") {
		t.Errorf("expected output to NOT contain root passwd info due to filter")
	}
}

func TestCredShadow_MissingFiles(t *testing.T) {
	setMockOSReadFile(t, map[string]string{})

	args := credHarvestArgs{Action: "shadow"}
	result := credShadow(args)

	if result.Status != "success" {
		t.Fatalf("expected status 'success', got '%s'", result.Status)
	}

	output := result.Output
	if !strings.Contains(output, "Error: open /etc/shadow: file does not exist") {
		t.Errorf("expected output to contain error for /etc/shadow")
	}
	if !strings.Contains(output, "Error: open /etc/gshadow: file does not exist") {
		t.Errorf("expected output to contain error for /etc/gshadow")
	}
}

func TestCredShadow_NoHashesFound(t *testing.T) {
	mockFiles := map[string]string{
		"/etc/shadow":   "root:*:18000:0:99999:7:::\nuser1:!:18000:0:99999:7:::\n",
		"/etc/gshadow":  "root:*::\n",
	}
	setMockOSReadFile(t, mockFiles)

	args := credHarvestArgs{Action: "shadow"}
	result := credShadow(args)

	if !strings.Contains(result.Output, "(no password hashes found — accounts may be locked)") {
		t.Errorf("expected output to state no password hashes found in shadow")
	}
	if !strings.Contains(result.Output, "(no group passwords found)") {
		t.Errorf("expected output to state no password hashes found in gshadow")
	}
}

func TestCredShadow_MalformedFiles(t *testing.T) {
	mockFiles := map[string]string{
		"/etc/shadow":   "root\nuser1:\n\n", // no colon, one colon, empty line
		"/etc/passwd":   "root\nuser1:\n\n",
		"/etc/gshadow":  "root\nuser1:\n\n",
	}
	setMockOSReadFile(t, mockFiles)

	args := credHarvestArgs{Action: "shadow"}
	result := credShadow(args)

	if !strings.Contains(result.Output, "(no password hashes found — accounts may be locked)") {
		t.Errorf("expected output to handle malformed shadow")
	}
	if !strings.Contains(result.Output, "(no group passwords found)") {
		t.Errorf("expected output to handle malformed gshadow")
	}
}


func TestGetUserHomes_Success(t *testing.T) {
	tempDir1 := t.TempDir()
	tempDir2 := t.TempDir()

	// Create a non-existent dir path
	nonExistentDir := "/tmp/does-not-exist-12345"

	passwdContent := `root:x:0:0:root:/root:/bin/bash
user1:x:1000:1000:User1:` + tempDir1 + `:/bin/bash
user2:x:1001:1001:User2:` + tempDir2 + `:/bin/sh
user3:x:1002:1002:User3:` + nonExistentDir + `:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
invalid:x:1003:1003:Invalid
empty:x:1004:1004:Empty::/bin/bash
`

	mockFiles := map[string]string{
		"/etc/passwd": passwdContent,
	}
	setMockOSReadFile(t, mockFiles)

	homes := getUserHomes("")

	found1 := false
	found2 := false
	for _, h := range homes {
		if h == tempDir1 {
			found1 = true
		}
		if h == tempDir2 {
			found2 = true
		}
		if h == nonExistentDir {
			t.Errorf("Should not include non-existent dir: %s", h)
		}
		if h == "/nonexistent" || h == "/dev/null" || h == "" || h == "/" {
			t.Errorf("Should not include invalid/ignored home dir: %s", h)
		}
	}

	if !found1 {
		t.Errorf("expected homes to contain tempDir1: %s", tempDir1)
	}
	if !found2 {
		t.Errorf("expected homes to contain tempDir2: %s", tempDir2)
	}
}

func TestGetUserHomes_WithFilter(t *testing.T) {
	tempDir1 := t.TempDir()
	tempDir2 := t.TempDir()

	passwdContent := `user1:x:1000:1000:User1:` + tempDir1 + `:/bin/bash
user2:x:1001:1001:User2:` + tempDir2 + `:/bin/sh
`
	mockFiles := map[string]string{
		"/etc/passwd": passwdContent,
	}
	setMockOSReadFile(t, mockFiles)

	homes := getUserHomes("user1")

	if len(homes) != 1 {
		t.Fatalf("expected exactly 1 home dir, got %d", len(homes))
	}
	if homes[0] != tempDir1 {
		t.Errorf("expected home to be tempDir1, got %s", homes[0])
	}
}

func TestGetUserHomes_Fallback(t *testing.T) {
	// Mock an empty file system so /etc/passwd fails to open
	setMockOSReadFile(t, map[string]string{})

	homes := getUserHomes("")

	// If /etc/passwd fails, it falls back to os.UserHomeDir()
	userHome, err := os.UserHomeDir()
	if err == nil {
		if len(homes) != 1 {
			t.Fatalf("expected exactly 1 home dir from fallback, got %d", len(homes))
		}
		if homes[0] != userHome {
			t.Errorf("expected home to be %s, got %s", userHome, homes[0])
		}
	} else {
		if len(homes) != 0 {
			t.Fatalf("expected 0 home dirs when fallback also fails, got %d", len(homes))
		}
	}
}
