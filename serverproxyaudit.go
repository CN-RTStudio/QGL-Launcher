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
	return auditHasWarning(a.Findings, func(f ProxyFinding) bool {
		return !f.Blocking && f.Reason != proxyReasonOK && f.Reason != proxyReasonMissing
	})
}

func unquoteYAMLValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
func flattenYAML(data []byte) (map[string]string, []string) {
	out := map[string]string{}
	dups := []string{}
	type frame struct {
		indent int
		key    string
	}
	stack := []frame{}
	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := stripYAMLComment(strings.TrimRight(raw, "\r"))
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		body := strings.TrimSpace(line)
		if strings.HasPrefix(body, "- ") || body == "-" {
			continue
		}
		colon := strings.Index(body, ":")
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(body[:colon])
		if key == "" {
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		prefix := make([]string, 0, len(stack)+1)
		for _, f := range stack {
			prefix = append(prefix, f.key)
		}
		prefix = append(prefix, key)
		path := strings.Join(prefix, ".")
		value := unquoteYAMLValue(body[colon+1:])
		if value == "" {
			stack = append(stack, frame{indent: indent, key: key})
			continue
		}
		if _, ok := out[path]; ok {
			dups = append(dups, path)
		}
		out[path] = value
	}
	return out, dups
}

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
