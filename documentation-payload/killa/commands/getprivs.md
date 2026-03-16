+++
title = "getprivs"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows, macOS, and Linux
{{% /notice %}}

## Summary

List process privileges, capabilities, or entitlements. Cross-platform command with platform-specific output.

### Windows
- **list** â€” Show all token privileges with enabled/disabled status and descriptions
- **enable** â€” Enable a specific privilege (e.g., SeDebugPrivilege)
- **disable** â€” Disable a specific privilege
- **strip** â€” Disable all non-essential privileges (keeps only SeChangeNotifyPrivilege)

The `strip` action reduces EDR detection surface by disabling privileges that trigger alerts (e.g., SeDebugPrivilege, SeImpersonatePrivilege).

Key privileges:

- **SeDebugPrivilege** â€” Required for `getsystem` and process injection
- **SeImpersonatePrivilege** â€” Required for `steal-token` and `make-token`
- **SeBackupPrivilege** â€” Can read any file regardless of ACLs
- **SeRestorePrivilege** â€” Can write any file regardless of ACLs
- **SeTcbPrivilege** â€” Act as part of the operating system

### Linux
- **list** â€” Show effective and permitted process capabilities (CAP_SYS_ADMIN, CAP_NET_RAW, etc.), UID/GID, and security context (SELinux/AppArmor)
- enable/disable/strip actions are not supported

### macOS
- **list** â€” Show group memberships, sandbox status, and code signing entitlements
- enable/disable/strip actions are not supported

## Arguments

| Argument  | Required | Default | Description |
|-----------|----------|---------|-------------|
| action    | Yes      | list    | `list`, `enable`, `disable`, or `strip` (enable/disable/strip Windows only) |
| privilege | No       | ""      | Privilege name (required for `enable`/`disable`, Windows only) |

## Usage

### List privileges / capabilities
```
getprivs
getprivs -action list
```

### Enable a privilege (Windows only)
```
getprivs -action enable -privilege SeDebugPrivilege
```

### Disable a privilege (Windows only)
```
getprivs -action disable -privilege SeDebugPrivilege
```

### Strip all non-essential privileges (Windows only)
```
getprivs -action strip
```

## Output Format

Returns a JSON object with identity metadata and a privileges/capabilities array (rendered as sortable tables in the Mythic UI):

### Windows
```json
{
  "identity": "DOMAIN\\user",
  "source": "Process",
  "integrity": "High",
  "privileges": [
    {"name": "SeDebugPrivilege", "status": "Enabled", "description": "Debug programs"}
  ]
}
```

### Linux
```json
{
  "identity": "root (uid=0 euid=0 gid=0 egid=0)",
  "source": "root",
  "integrity": "Root | LSM: lockdown,capability,landlock,yama,apparmor,bpf",
  "privileges": [
    {"name": "CAP_SYS_ADMIN", "status": "Enabled", "description": "System administration (mount, sethostname, etc)"},
    {"name": "CAP_NET_RAW", "status": "Enabled", "description": "Use raw and packet sockets"}
  ]
}
```

### macOS
```json
{
  "identity": "gary (uid=501 euid=501 gid=20 egid=20)",
  "source": "process",
  "integrity": "Standard",
  "privileges": [
    {"name": "group:admin", "status": "Enabled", "description": "Administrative group â€” sudo access"},
    {"name": "sandbox", "status": "Disabled", "description": "Process is not sandboxed â€” unrestricted"}
  ]
}
```

## MITRE ATT&CK Mapping

- T1134.002 â€” Access Token Manipulation: Create Process with Token
