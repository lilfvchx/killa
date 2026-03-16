+++
title = "proxy-check"
chapter = false
weight = 204
hidden = false
+++

## Summary

Detect proxy settings from multiple sources: environment variables, OS-level configuration, and the Go HTTP transport's built-in proxy resolution. Optionally test connectivity through detected proxies.

Useful for understanding the network path before pivoting or exfiltrating data â€” proxies may intercept, log, or block C2 traffic.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| test_url | No | | URL to test proxy connectivity (e.g., `http://example.com`) |

## Usage

Check all proxy settings:
```
proxy-check
```

Check proxy settings and test connectivity:
```
proxy-check -test_url http://example.com
```

## Output Sections

1. **Environment Variables** â€” `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY` (and lowercase variants)
2. **Platform-Specific Settings:**
   - **Windows:** Registry keys `HKCU\...\Internet Settings` (ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL) and WinHTTP settings
   - **Linux:** `/etc/apt/apt.conf.d/proxy.conf`, `/etc/environment`, `/etc/profile.d/` proxy scripts
   - **macOS:** `/Library/Preferences/SystemConfiguration/preferences.plist` (ProxyAutoConfig, HTTPProxy, SOCKSProxy)
3. **Go Transport Proxy Detection** â€” What proxy the Go HTTP client would use for `http://` and `https://` URLs
4. **Connectivity Test** (if `test_url` provided) â€” HTTP response status through detected proxy

## MITRE ATT&CK Mapping

- **T1016** â€” System Network Configuration Discovery
