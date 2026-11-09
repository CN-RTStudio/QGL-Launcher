package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

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

func pcReadBounded(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	limited := io.LimitReader(f, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("超过体积上限 %d", maxBytes)
	}
	return data, nil
}
