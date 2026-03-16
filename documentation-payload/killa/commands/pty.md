+++
title = "pty"
chapter = false
weight = 113
hidden = false
+++

## Summary

Start an interactive PTY (pseudo-terminal) shell session using Mythic's interactive tasking feature. Allocates a real PTY device and attaches a shell process, providing full terminal emulation with support for interactive programs (vim, top, htop, etc.), tab completion, command history, and control characters.

{{% notice info %}}Linux / macOS Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| shell | No | Shell binary path (default: auto-detect from $SHELL, falls back to /bin/bash or /bin/sh) |
| rows | No | Initial terminal rows (default: 24) |
| cols | No | Initial terminal columns (default: 80) |

## Usage

```
# Start interactive PTY with default shell
pty

# Start with a specific shell
pty -shell /bin/zsh

# Start with custom terminal size
pty -rows 40 -cols 120
```

## How It Works

1. **PTY allocation** â€” Opens a pseudo-terminal pair (master/slave) via `/dev/ptmx`
2. **Shell start** â€” Launches the detected or specified shell attached to the PTY slave
3. **Bidirectional I/O** â€” Agent reads shell output from PTY master and sends to Mythic; receives user input from Mythic and writes to PTY master
4. **Control characters** â€” Ctrl+C, Ctrl+D, Ctrl+Z, and other control sequences are translated and forwarded to the PTY
5. **Session end** â€” Shell exit or `jobkill` terminates the PTY session

## OPSEC Considerations

- Spawns a child shell process (visible in process listings)
- The PTY device is allocated natively (no external binary needed for PTY setup)
- Interactive output is streamed via the agent's normal C2 polling interval
- Lower sleep intervals provide more responsive terminal interaction
- Use `jobkill` to terminate the session when done

## MITRE ATT&CK Mapping

- **T1059** â€” Command and Scripting Interpreter
