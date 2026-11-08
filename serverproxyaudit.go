package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
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
	data, err := os.ReadFile(path)
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

func auditProxySecretFile(audit *ServerProxyAudit, serverDir string) string {
	path := filepath.Join(serverDir, "forwarding.secret")
	info, err := os.Lstat(path)
	if err != nil {
		audit.Findings = append(audit.Findings, ProxyFinding{File: "forwarding.secret", Reason: proxyReasonSecretMissing, Detail: "Velocity 需要转发密钥文件", Blocking: false})
		return ""
	}
	audit.Files = append(audit.Files, "forwarding.secret")
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, ProxyFinding{File: "forwarding.secret", Reason: proxyReasonSecretSymlink, Detail: "密钥文件是符号链接", Blocking: true})
		return ""
	}
	if info.Mode().Perm()&0o044 != 0 {
		audit.Findings = append(audit.Findings, ProxyFinding{File: "forwarding.secret", Reason: proxyReasonSecretPermissive, Detail: "同机其他账户可读该密钥", Blocking: false})
	}
	data, err := os.ReadFile(path)
	if err != nil {
		audit.Findings = append(audit.Findings, ProxyFinding{File: "forwarding.secret", Reason: proxyReasonUnreadable, Detail: "密钥文件不可读", Blocking: false})
		return ""
	}
	return strings.TrimSpace(string(data))
}

func AuditServerProxyTrust(serverDir string) *ServerProxyAudit {
	audit := &ServerProxyAudit{}
	if strings.TrimSpace(serverDir) == "" {
		audit.Findings = append(audit.Findings, ProxyFinding{Reason: proxyReasonMissing, Detail: "未提供服务器目录"})
		return audit
	}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		audit.Findings = append(audit.Findings, ProxyFinding{Reason: proxyReasonMissing, Detail: "服务器目录不存在"})
		return audit
	}

	props := map[string]string{}
	propsPath := filepath.Join(serverDir, "server.properties")
	if data, reason := readProxyConfig(propsPath); reason == "" {
		audit.Files = append(audit.Files, "server.properties")
		props = proxyProperties(data)
	} else if reason != proxyReasonMissing {
		audit.Findings = append(audit.Findings, ProxyFinding{File: "server.properties", Reason: reason, Detail: "服务器主配置不可用", Blocking: reason == proxyReasonSymlink})
	}

	yamlCandidates := []string{"spigot.yml", "paper-global.yml", filepath.Join("config", "paper-global.yml")}
	yamlMaps := map[string]map[string]string{}
	for _, name := range yamlCandidates {
		data, reason := readProxyConfig(filepath.Join(serverDir, name))
		if reason == proxyReasonMissing {
			continue
		}
		audit.Files = append(audit.Files, name)
		if reason != "" {
			audit.Findings = append(audit.Findings, ProxyFinding{File: name, Reason: reason, Detail: "代理配置文件不可用", Blocking: reason == proxyReasonSymlink || reason == proxyReasonTooLarge})
			continue
		}
		flat, dups := flattenYAML(data)
		for _, d := range dups {
			audit.Findings = append(audit.Findings, ProxyFinding{File: name, Key: d, Reason: proxyReasonDuplicateKey, Detail: "重复的配置键，最终值取决于解析器", Blocking: false})
		}
		yamlMaps[name] = flat
	}

	bungeeEnabled := false
	velocityEnabled := false
	velocitySecret := ""
	for name, flat := range yamlMaps {
		if strings.EqualFold(flat["settings.bungeecord"], "true") {
			bungeeEnabled = true
			audit.Findings = append(audit.Findings, ProxyFinding{File: name, Key: "settings.bungeecord", Value: "true", Reason: proxyReasonLegacyBungee, Detail: "旧式 BungeeCord 转发", Blocking: false})
		}
		if strings.EqualFold(flat["proxies.bungee-cord.online-mode"], "true") {
			bungeeEnabled = true
		}
		if strings.EqualFold(flat["proxies.velocity.enabled"], "true") {
			velocityEnabled = true
			if v, ok := flat["proxies.velocity.secret"]; ok {
				velocitySecret = v
			}
		}
	}

	audit.ProxyEnabled = bungeeEnabled || velocityEnabled
	if velocityEnabled {
		if audit.Provider == "" {
			audit.Provider = "velocity"
		}
	} else if bungeeEnabled {
		audit.Provider = "bungeecord"
	}

	if !audit.ProxyEnabled {
		audit.Findings = append(audit.Findings, ProxyFinding{Reason: proxyReasonOK, Detail: "未启用代理转发"})
		return audit
	}

	bind := props["server-ip"]
	bindSafe := isLoopbackBind(bind)
	if !bindSafe {
		detail := "后端绑定非回环地址，可绕过代理直连"
		if isWildcardBind(bind) {
			detail = "后端监听通配地址，可绕过代理直连伪造身份"
		}
		audit.Findings = append(audit.Findings, ProxyFinding{File: "server.properties", Key: "server-ip", Value: bind, Reason: proxyReasonProxyExposed, Detail: detail, Blocking: true})
	}

	if strings.EqualFold(props["online-mode"], "false") && !bindSafe {
		audit.Findings = append(audit.Findings, ProxyFinding{File: "server.properties", Key: "online-mode", Value: "false", Reason: proxyReasonOnlineModeOff, Detail: "后端关闭正版验证且监听可直连地址，身份校验被完全绕过", Blocking: true})
	}

	if velocityEnabled {
		secret := velocitySecret
		if secret == "" {
			secret = auditProxySecretFile(audit, serverDir)
		}
		reason, detail, blocking := proxySecretVerdict(secret)
		if reason != proxyReasonOK {
			audit.Findings = append(audit.Findings, ProxyFinding{File: "forwarding.secret", Key: "proxies.velocity.secret", Value: secret, Reason: reason, Detail: detail, Blocking: blocking})
		}
	}

	return audit
}
