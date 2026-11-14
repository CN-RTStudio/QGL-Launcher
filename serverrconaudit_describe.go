package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *ServerRconAudit) Describe() string {
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Key == "" {
			parts = append(parts, fmt.Sprintf("%s: %s", f.Reason, f.Detail))
			continue
		}
		if f.Value != "" {
			parts = append(parts, fmt.Sprintf("%s=%q(%s): %s", f.Key, f.Value, f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s(%s): %s", f.Key, f.Reason, f.Detail))
	}
	return strings.Join(parts, "；")
}

func AuditServerRcon(serverDir string) (*ServerRconAudit, error) {
	path := filepath.Join(serverDir, "server.properties")
	audit := &ServerRconAudit{Path: path}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			audit.Findings = append(audit.Findings, RconFinding{
				Reason: rconReasonMissing, Detail: "server.properties 不存在，无法审计 RCON/Query 暴露面",
			})
			return audit, nil
		}
		return nil, fmt.Errorf("读取 server.properties 属性失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, RconFinding{
			Reason: rconReasonSymlink, Detail: "server.properties 是符号链接", Blocking: true,
		})
		return audit, nil
	}
	if !info.Mode().IsRegular() {
		audit.Findings = append(audit.Findings, RconFinding{
			Reason: rconReasonUnreadable, Detail: "server.properties 不是普通文件", Blocking: true,
		})
		return audit, nil
	}
	if info.Size() > int64(localTextConfigMaxBytes) {
		audit.Findings = append(audit.Findings, RconFinding{
			Reason: rconReasonUnreadable, Detail: "server.properties 体积异常，跳过审计", Blocking: true,
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
	audit.auditRcon(props)
	audit.auditQuery(props)
	return audit, nil
}

func (a *ServerRconAudit) auditDuplicateKeys(props *serverProperties) {
	counts := make(map[string]int, len(props.lines))
	for _, line := range props.lines {
		if line.isPair {
			counts[line.key]++
		}
	}
	for key, count := range counts {
		if count < 2 {
			continue
		}
		a.Findings = append(a.Findings, RconFinding{
			Key: key, Reason: rconReasonDuplicateKey,
			Detail: fmt.Sprintf("键出现 %d 次，生效值不确定", count),
		})
	}
}
