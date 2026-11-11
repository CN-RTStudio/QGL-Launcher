package main

import (
	"strings"
)

const (
	pcReasonOK              = "ok"
	pcReasonMissing         = "missing"
	pcReasonUnreadable      = "unreadable"
	pcReasonTooLarge        = "too-large"
	pcReasonSymlink         = "symlink"
	pcReasonTooMany         = "too-many"
	pcReasonDangerousToggle = "dangerous-toggle"
	pcReasonPlaintextSecret = "plaintext-secret"
	pcReasonWorldReadable   = "world-readable"
	pcReasonDepthExceeded   = "depth-exceeded"

	pcMaxFileBytes = 512 << 10
	pcMaxFiles     = 512
	pcMaxDepth     = 3
	pcMaxFindings  = 96
	pcMaxLineScan  = 4096
)

var pcConfigExts = []string{".yml", ".yaml", ".json", ".toml", ".conf", ".properties"}

var pcDangerousKeys = []string{
	"bypass-permissions",
	"bypass_permissions",
	"bypasspermissions",
	"allow-unsafe",
	"allow_unsafe",
	"allowunsafe",
	"allow-flight",
	"allow_flight",
	"allowflight",
	"debug",
	"disable-auth",
	"disable_auth",
	"disableauth",
	"skip-auth",
	"auth-bypass",
	"op-override",
}

var pcSecretKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"api-key",
	"apikey",
	"api_key",
	"access-key",
	"private-key",
	"rcon-password",
}

func pcLookupKey(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return "", "", false
	}
	cut := strings.IndexAny(trimmed, ":=")
	if cut <= 0 {
		return "", "", false
	}
	key := strings.ToLower(strings.TrimSpace(trimmed[:cut]))
	value := strings.TrimSpace(trimmed[cut+1:])
	key = strings.Trim(key, `"'`)
	return key, value, true
}
func pcBoolValue(value string) (bool, bool) {
	cleaned := strings.Trim(strings.TrimSpace(value), `"'`)
	cleaned = strings.TrimRight(cleaned, ",")
	switch strings.ToLower(cleaned) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	}
	return false, false
}
func pcValueEmpty(value string) bool {
	cleaned := strings.Trim(strings.TrimSpace(value), `"'`)
	cleaned = strings.TrimRight(cleaned, ",")
	return cleaned == "" || cleaned == "''" || cleaned == `""` || cleaned == "null"
}

func pcScanLines(audit *PluginConfigAudit, name string, data []byte) {
	lines := strings.Split(string(data), "\n")
	if len(lines) > pcMaxLineScan {
		lines = lines[:pcMaxLineScan]
	}
	for _, line := range lines {
		key, value, ok := pcLookupKey(line)
		if !ok {
			continue
		}
		plainKey := key
		if idx := strings.LastIndex(plainKey, "."); idx >= 0 {
			plainKey = plainKey[idx+1:]
		}
		for _, danger := range pcDangerousKeys {
			if plainKey != danger {
				continue
			}
			if enabled, ok := pcBoolValue(value); ok && enabled {
				audit.add(name, pcReasonDangerousToggle, "启用了危险开关 "+plainKey, true)
			}
			break
		}
		for _, secret := range pcSecretKeys {
			if plainKey != secret {
				continue
			}
			if !pcValueEmpty(value) && !strings.HasPrefix(strings.TrimSpace(value), "${") {
				audit.add(name, pcReasonPlaintextSecret, "明文凭据字段 "+plainKey, false)
			}
			break
		}
	}
}
