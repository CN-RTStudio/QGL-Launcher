package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

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

func (a *ServerProxyAudit) Codes() []string {
	seen := map[string]bool{}
	codes := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if seen[f.Reason] {
			continue
		}
		seen[f.Reason] = true
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}
func (a *ServerProxyAudit) Describe() string {
	if a == nil || len(a.Findings) == 0 {
		return "代理信任审计: 未发现配置文件"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == proxyReasonOK || f.Reason == proxyReasonMissing {
			continue
		}
		if f.Key != "" {
			parts = append(parts, fmt.Sprintf("%s %s=%q %s(%s)", f.File, f.Key, f.Value, f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %s(%s)", f.File, f.Reason, f.Detail))
	}
	if len(parts) == 0 {
		return "代理信任审计: 通过"
	}
	return strings.Join(parts, "; ")
}

func (a *ServerProxyAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f ProxyFinding) bool { return f.Blocking }, func(f ProxyFinding) bool {
		return !f.Blocking && f.Reason != proxyReasonOK && f.Reason != proxyReasonMissing
	})
	return fmt.Sprintf("代理信任 %v(%s)，阻断 %d，告警 %d", a.ProxyEnabled, a.Provider, blocking, warnings)
}

func stripYAMLComment(line string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				return line[:i]
			}
		}
	}
	return line
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
