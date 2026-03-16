+++
title = "env"
chapter = false
weight = 103
hidden = false
+++

## Summary

List, get, set, or unset environment variables for the agent process. Changes affect the agent's own environment and are inherited by child processes (e.g., `run`, `shell`).

Cross-platform â€” works on Windows, Linux, and macOS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | list | Action: `list`, `get`, `set`, or `unset` |
| name | For get/set/unset | â€” | Variable name |
| value | For set | â€” | Variable value |
| filter | No | â€” | Filter pattern for list action (case-insensitive name match) |

### Actions

- **list** â€” Show all environment variables, optionally filtered by name
- **get** â€” Get the value of a specific variable
- **set** â€” Create or update a variable
- **unset** â€” Remove a variable

## Usage
```
# List all environment variables
env

# Filter by name (backward compatible)
env -action list -filter path

# Get a specific variable
env -action get -name PATH

# Set a variable
env -action set -name MYVAR -value "hello world"

# Unset a variable
env -action unset -name MYVAR
```

## Operational Notes

- `set` and `unset` modify the agent process environment â€” changes persist for the agent's lifetime
- Child processes spawned via `run` or `shell` inherit the modified environment
- Useful for manipulating `PATH` before command execution or planting variables for application behavior
- `list` without filters returns all variables sorted alphabetically

## MITRE ATT&CK Mapping

- T1082 â€” System Information Discovery
