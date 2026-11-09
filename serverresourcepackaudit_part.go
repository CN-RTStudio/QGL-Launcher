package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
