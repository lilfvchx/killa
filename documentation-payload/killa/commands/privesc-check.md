+++
title = "privesc-check"
chapter = false
weight = 100
hidden = false
+++

## Summary

Cross-platform privilege escalation enumeration. Scans for common privilege escalation vectors with platform-specific checks for Windows, Linux, and macOS.

- **Windows:** Token privileges (potato attacks, SeDebug, SeBackup), unquoted service paths, modifiable service binaries, AlwaysInstallElevated, auto-logon credentials, UAC configuration, LSA protection, writable PATH directories, unattended install files
- **Linux:** SUID/SGID binaries, file capabilities, sudo rules, writable paths, containers
- **macOS:** LaunchDaemons/Agents, TCC database, dylib hijacking, SIP status

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | all | Check to perform (see platform-specific actions below) |

### Shared Actions (All Platforms)

- **all** â€” Run all platform-appropriate checks
- **writable** â€” Find writable PATH directories and sensitive files/paths

### Windows-Only Actions

- **privileges** â€” Enumerate token privileges, flag exploitable ones (SeImpersonate, SeDebug, SeBackup, etc.) with exploitation guidance
- **services** â€” Check for unquoted service paths, modifiable service binaries, and writable binary directories
- **registry** â€” Check AlwaysInstallElevated, auto-logon credentials, LSA protection (RunAsPPL), Credential Guard, WSUS configuration
- **uac** â€” Report UAC configuration (EnableLUA, ConsentPromptBehavior, Secure Desktop, FilterAdminToken)
- **unattend** â€” Search for unattended install files (sysprep/Unattend.xml) and other credential-containing files

### Linux-Only Actions

- **suid** â€” Find SUID/SGID binaries, flag exploitable ones (find, python, docker, etc.)
- **sudo** â€” Check `sudo -l` (non-interactive), read `/etc/sudoers` if accessible
- **capabilities** â€” Enumerate file capabilities via `getcap` and current process capabilities
- **container** â€” Detect Docker, Kubernetes, LXC, overlay FS, container cgroups

### macOS-Only Actions

- **launchdaemons** â€” Check for writable LaunchDaemons/LaunchAgents plists (persistence + privesc)
- **tcc** â€” Inspect TCC database for granted permissions (Full Disk Access, Accessibility, etc.)
- **dylib** â€” Check DYLD_* environment variables, Hardened Runtime status, writable library paths
- **sip** â€” Check System Integrity Protection and Authenticated Root status

## Usage

```
privesc-check -action all
privesc-check -action privileges
privesc-check -action services
privesc-check -action registry
privesc-check -action uac
privesc-check -action suid
privesc-check -action launchdaemons
```

### Example Output (Windows, all)

```
=== WINDOWS PRIVILEGE ESCALATION CHECK ===

--- Token Privileges ---
Token privileges (23 total):
  SeIncreaseQuotaPrivilege               [Disabled]
  SeSecurityPrivilege                    [Disabled]
  SeBackupPrivilege                      [Disabled]
  SeImpersonatePrivilege                 [Enabled]
  ...

[!] EXPLOITABLE privileges (3):
  [!] SeImpersonatePrivilege              [Enabled]  â†’ Potato attacks (JuicyPotato, PrintSpoofer, GodPotato) â†’ SYSTEM
  [*] SeBackupPrivilege                   [Disabled] â†’ Read any file (SAM, SYSTEM hives, NTDS.dit)
  [!] SeDebugPrivilege                    [Enabled]  â†’ Inject into/dump any process including LSASS

Note: Disabled privileges can be enabled with 'getprivs -action enable -privilege <name>'

Integrity Level: High (S-1-16-12288) (elevated admin)

--- UAC Configuration ---
UAC is enabled (EnableLUA = 1)
Admin consent prompt behavior: Prompt for consent for non-Windows binaries (5) â€” DEFAULT
[*] Standard config â€” UAC bypass via auto-elevating binaries possible (fodhelper, computerdefaults, sdclt)

--- Service Misconfigurations ---
Checked 247 services:

Unquoted service paths (2):
  VulnerableService
    Path: C:\Program Files\Vulnerable App\service.exe -start
    Start: Auto
[!] Unquoted paths with spaces allow binary planting in intermediate directories

--- Registry Checks ---
AlwaysInstallElevated:
  Not enabled (safe)

Auto-Logon Credentials:
  Not configured

LSA Protection:
  [!] LSA Protection (RunAsPPL) is NOT enabled â€” LSASS can be dumped
```

## MITRE ATT&CK Mapping

| Technique ID | Name |
|--------------|------|
| T1548 | Abuse Elevation Control Mechanism |
| T1548.001 | Setuid and Setgid |
| T1548.002 | Bypass User Account Control |
| T1574.009 | Path Interception by Unquoted Path |
| T1552.001 | Unsecured Credentials: Credentials In Files |
| T1613 | Container and Resource Discovery |
| T1082 | System Information Discovery |
