package main

import (
	"fmt"
	"os"
	"path/filepath"
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
