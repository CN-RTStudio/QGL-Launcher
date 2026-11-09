package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	proxyReasonOK                = "ok"
	proxyReasonMissing           = "missing"
	proxyReasonSymlink           = "symlink"
	proxyReasonTooLarge          = "too-large"
	proxyReasonUnreadable        = "unreadable"
	proxyReasonBadYAML           = "bad-yaml"
	proxyReasonDuplicateKey      = "duplicate-key"
	proxyReasonProxyExposed      = "proxy-exposed"
	proxyReasonOnlineModeOff     = "proxy-online-mode-off"
	proxyReasonLegacyBungee      = "legacy-bungee"
	proxyReasonEmptySecret       = "empty-forwarding-secret"
	proxyReasonWeakSecret        = "weak-forwarding-secret"
	proxyReasonPlaceholderSecret = "placeholder-forwarding-secret"
	proxyReasonSecretMissing     = "secret-file-missing"
	proxyReasonSecretPermissive  = "secret-file-permissive"
	proxyReasonSecretSymlink     = "secret-file-symlink"
	proxyMaxConfigBytes          = 1 << 20
	proxyMinSecretRunes          = 12
	proxyMaxSecretRunes          = 256
)

var proxyPlaceholderSecrets = map[string]bool{
	"": true, "secret": true, "changeme": true, "change-me": true,
	"your-secret-here": true, "yoursecret": true, "password": true,
	"velocity-secret": true, "forwarding-secret": true, "todo": true,
}

type ProxyFinding struct {
	File     string
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerProxyAudit struct {
	Files        []string
	ProxyEnabled bool
	Provider     string
	Findings     []ProxyFinding
}

func (a *ServerProxyAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ProxyFinding) bool { return f.Blocking })
}

func (a *ServerProxyAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != proxyReasonOK && f.Reason != proxyReasonMissing {
			return true
		}
	}
	return false
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
	blocking := 0
	warnings := 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
			continue
		}
		if f.Reason != proxyReasonOK && f.Reason != proxyReasonMissing {
			warnings++
		}
	}
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
