package main

import (
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
