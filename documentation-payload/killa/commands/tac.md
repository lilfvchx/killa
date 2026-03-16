+++
title = "tac"
chapter = false
weight = 180
hidden = false
+++

## Summary

Print file lines in reverse order. Like Unix `tac` â€” useful for viewing logs from newest to oldest without downloading the entire file.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | | Path to file to reverse |

## Usage

Reverse a log file:
```
tac -path /var/log/auth.log
```

## MITRE ATT&CK Mapping

- **T1083** â€” File and Directory Discovery
