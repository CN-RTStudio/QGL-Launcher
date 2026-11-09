package main

import (
	"fmt"
	"net/url"
	"strings"
)

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
