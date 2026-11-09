package main

import (
	"fmt"
	"os"
	"strings"
)

func proxyProperties(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			idx = strings.Index(line, ":")
		}
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(line[idx+1:])
	}
	return out
}

func readProxyConfig(path string) ([]byte, string) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, proxyReasonMissing
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, proxyReasonSymlink
	}
	if !info.Mode().IsRegular() {
		return nil, proxyReasonUnreadable
	}
	if info.Size() > proxyMaxConfigBytes {
		return nil, proxyReasonTooLarge
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return nil, proxyReasonUnreadable
	}
	return data, ""
}

func isLoopbackBind(value string) bool {
	v := strings.TrimSpace(strings.ToLower(value))
	if v == "" {
		return false
	}
	switch v {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return strings.HasPrefix(v, "127.") || strings.HasPrefix(v, "::1")
}

func isWildcardBind(value string) bool {
	v := strings.TrimSpace(strings.ToLower(value))
	return v == "" || v == "0.0.0.0" || v == "*" || v == "::" || v == "[::]"
}

func proxySecretVerdict(secret string) (string, string, bool) {
	s := strings.TrimSpace(secret)
	if proxyPlaceholderSecrets[strings.ToLower(s)] {
		return proxyReasonPlaceholderSecret, "转发密钥为空或仍是示例值", true
	}
	if len([]rune(s)) < proxyMinSecretRunes {
		return proxyReasonWeakSecret, fmt.Sprintf("转发密钥长度 %d 低于 %d", len([]rune(s)), proxyMinSecretRunes), false
	}
	if len([]rune(s)) > proxyMaxSecretRunes {
		return proxyReasonPlaceholderSecret, "转发密钥过长", true
	}
	if strings.ContainsAny(s, " \t") {
		return proxyReasonPlaceholderSecret, "转发密钥含空白字符", true
	}
	return proxyReasonOK, "", false
}
