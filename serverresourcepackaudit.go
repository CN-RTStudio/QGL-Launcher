package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	packReasonOK           = "ok"
	packReasonMissing      = "missing"
	packReasonSymlink      = "symlink"
	packReasonUnreadable   = "unreadable"
	packReasonTooLarge     = "too-large"
	packReasonBadScheme    = "bad-scheme"
	packReasonInsecure     = "insecure-transport"
	packReasonUserinfo     = "url-userinfo"
	packReasonTooLong      = "url-too-long"
	packReasonBadHash      = "bad-hash"
	packReasonMissingHash  = "missing-hash"
	packReasonPlaceholder  = "placeholder-hash"
	packReasonBadPrompt    = "bad-prompt"
	packReasonDuplicateKey = "duplicate-key"
	packMaxURLLength       = 2048
	packMaxPromptRunes     = 256
	packSHA1HexLength      = 40
)

type PackFinding struct {
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerResourcePackAudit struct {
	Path     string
	Present  bool
	PackURL  string
	Findings []PackFinding
}

func (a *ServerResourcePackAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f PackFinding) bool { return f.Blocking })
}

func (a *ServerResourcePackAudit) HasWarnings() bool {
	if a == nil {
		return false
	}
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != packReasonOK {
			return true
		}
	}
	return false
}

func (a *ServerResourcePackAudit) Codes() []string {
	if a == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(a.Findings))
	codes := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == packReasonOK {
			continue
		}
		if _, ok := seen[f.Reason]; ok {
			continue
		}
		seen[f.Reason] = struct{}{}
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}

func (a *ServerResourcePackAudit) Describe() string {
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == packReasonOK {
			continue
		}
		if f.Key == "" {
			parts = append(parts, fmt.Sprintf("%s: %s", f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%q(%s): %s", f.Key, f.Value, f.Reason, f.Detail))
	}
	return strings.Join(parts, "；")
}

func AuditServerResourcePack(serverDir string) (*ServerResourcePackAudit, error) {
	path := filepath.Join(serverDir, "server.properties")
	audit := &ServerResourcePackAudit{Path: path}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			audit.Findings = append(audit.Findings, PackFinding{
				Reason: packReasonMissing, Detail: "server.properties 不存在，无法审计资源包下载策略",
			})
			return audit, nil
		}
		return nil, fmt.Errorf("读取 server.properties 属性失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, PackFinding{
			Reason: packReasonSymlink, Detail: "server.properties 是符号链接", Blocking: true,
		})
		return audit, nil
	}
	if !info.Mode().IsRegular() {
		audit.Findings = append(audit.Findings, PackFinding{
			Reason: packReasonUnreadable, Detail: "server.properties 不是普通文件", Blocking: true,
		})
		return audit, nil
	}
	if info.Size() > int64(localTextConfigMaxBytes) {
		audit.Findings = append(audit.Findings, PackFinding{
			Reason:   packReasonTooLarge,
			Detail:   fmt.Sprintf("server.properties 大小 %d 字节，超过 %d 上限", info.Size(), localTextConfigMaxBytes),
			Blocking: true,
		})
		return audit, nil
	}
	data, err := readBoundedFile(path, int64(localTextConfigMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("读取 server.properties 失败: %w", err)
	}
	props := parseServerProperties(data)
	audit.Present = true
	audit.auditDuplicateKeys(props)

	raw, ok := props.Get("resource-pack")
	if !ok || strings.TrimSpace(raw) == "" {
		return audit, nil
	}
	audit.PackURL = strings.TrimSpace(raw)
	audit.auditURL(audit.PackURL)
	audit.auditHash(props)
	audit.auditPrompt(props)
	return audit, nil
}

func (a *ServerResourcePackAudit) auditDuplicateKeys(props *serverProperties) {
	counts := make(map[string]int, len(props.lines))
	for _, line := range props.lines {
		if !line.isPair {
			continue
		}
		counts[line.key]++
	}
	for key, count := range counts {
		if count < 2 {
			continue
		}
		a.Findings = append(a.Findings, PackFinding{
			Key: key, Reason: packReasonDuplicateKey,
			Detail: fmt.Sprintf("键出现 %d 次，最终生效值取决于解析顺序", count),
		})
	}
}

func (a *ServerResourcePackAudit) auditURL(raw string) {
	if len(raw) > packMaxURLLength {
		a.Findings = append(a.Findings, PackFinding{
			Key: "resource-pack", Value: raw[:64] + "...", Reason: packReasonTooLong,
			Detail: fmt.Sprintf("资源包 URL 长度 %d，超过 %d", len(raw), packMaxURLLength), Blocking: true,
		})
		return
	}
	if containsControlByte(raw) || strings.ContainsAny(raw, " \t") {
		a.Findings = append(a.Findings, PackFinding{
			Key: "resource-pack", Value: raw, Reason: packReasonBadScheme,
			Detail: "资源包 URL 含控制字符或空白", Blocking: true,
		})
		return
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		a.Findings = append(a.Findings, PackFinding{
			Key: "resource-pack", Value: raw, Reason: packReasonBadScheme,
			Detail: "资源包 URL 无法解析或缺少主机名", Blocking: true,
		})
		return
	}
	if parsed.User != nil {
		a.Findings = append(a.Findings, PackFinding{
			Key: "resource-pack", Value: raw, Reason: packReasonUserinfo,
			Detail: "URL 内嵌用户名/口令，会随服务器配置一起泄露", Blocking: true,
		})
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		a.Findings = append(a.Findings, PackFinding{
			Key: "resource-pack", Value: raw, Reason: packReasonInsecure,
			Detail: "资源包走明文 HTTP，客户端下载内容可被中间人替换", Blocking: false,
		})
	default:
		a.Findings = append(a.Findings, PackFinding{
			Key: "resource-pack", Value: raw, Reason: packReasonBadScheme,
			Detail: "资源包 URL 只允许 http/https", Blocking: true,
		})
	}
}

func (a *ServerResourcePackAudit) auditHash(props *serverProperties) {
	raw, ok := props.Get("resource-pack-sha1")
	if !ok || strings.TrimSpace(raw) == "" {
		a.Findings = append(a.Findings, PackFinding{
			Key: "resource-pack-sha1", Reason: packReasonMissingHash,
			Detail: "已配置资源包但没有 SHA-1，客户端无法校验下载内容", Blocking: false,
		})
		return
	}
	value := strings.ToLower(strings.TrimSpace(raw))
	if len(value) != packSHA1HexLength || !IsLowerHex(value, packSHA1HexLength) {
		a.Findings = append(a.Findings, PackFinding{
			Key: "resource-pack-sha1", Value: raw, Reason: packReasonBadHash,
			Detail: "SHA-1 必须是 40 位十六进制字符串", Blocking: true,
		})
		return
	}
	if strings.Trim(value, "0") == "" {
		a.Findings = append(a.Findings, PackFinding{
			Key: "resource-pack-sha1", Value: raw, Reason: packReasonPlaceholder,
			Detail: "SHA-1 为全零占位值，等于没有校验", Blocking: true,
		})
	}
}

func (a *ServerResourcePackAudit) auditPrompt(props *serverProperties) {
	raw, ok := props.Get("resource-pack-prompt")
	if !ok || raw == "" {
		return
	}
	if containsControlByte(raw) || len([]rune(raw)) > packMaxPromptRunes {
		a.Findings = append(a.Findings, PackFinding{
			Key: "resource-pack-prompt", Value: raw, Reason: packReasonBadPrompt,
			Detail: "资源包提示文案含控制字符或超过 256 字符", Blocking: false,
		})
	}
}

func (a *ServerResourcePackAudit) Summary() string {
	if !a.Present {
		return "资源包策略未审计"
	}
	if a.PackURL == "" {
		return "未配置资源包"
	}
	if len(a.Findings) == 0 {
		return "资源包下载策略校验通过"
	}
	return a.Describe()
}
