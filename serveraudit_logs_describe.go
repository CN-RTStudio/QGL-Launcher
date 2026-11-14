package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *ServerLogAudit) Describe() string {
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Name == "" {
			parts = append(parts, fmt.Sprintf("%s: %s", f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s(%s): %s", f.Name, f.Reason, f.Detail))
	}
	return strings.Join(parts, "；")
}

func AuditServerLogs(serverDir string) (*ServerLogAudit, error) {
	dir := filepath.Join(serverDir, "logs")
	audit := &ServerLogAudit{Dir: dir}
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return audit, nil
		}
		return nil, fmt.Errorf("读取 logs 目录属性失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, LogFinding{
			Name: "logs", Reason: logAuditReasonSymlink,
			Detail: "logs 目录是符号链接，服务端日志可能写到服务器目录之外", Blocking: true,
		})
		return audit, nil
	}
	if !info.IsDir() {
		audit.Findings = append(audit.Findings, LogFinding{
			Name: "logs", Reason: logAuditReasonNotRegular,
			Detail: "logs 存在但不是目录", Blocking: true,
		})
		return audit, nil
	}
	audit.Present = true
	if info.Mode().Perm()&0o002 != 0 {
		audit.Findings = append(audit.Findings, LogFinding{
			Name: "logs", Reason: logAuditReasonWorldWritable,
			Detail: "logs 目录对其他用户可写，日志可被替换或注入", Blocking: false,
		})
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取 logs 目录失败: %w", err)
	}
	audit.Entries = len(entries)
	rotated := 0
	scanned := 0
	for _, entry := range entries {
		if scanned >= serverLogMaxEntries {
			audit.Findings = append(audit.Findings, LogFinding{
				Name: "logs", Reason: logAuditReasonTooMany,
				Detail: fmt.Sprintf("日志目录条目超过 %d，后续条目未审计", serverLogMaxEntries),
			})
			break
		}
		scanned++
		name := entry.Name()
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".log") || strings.HasSuffix(lower, ".log.gz") {
			rotated++
		}
		audit.auditLogEntry(dir, entry)
	}
	if rotated > serverLogMaxRotated {
		audit.Findings = append(audit.Findings, LogFinding{
			Name: "logs", Reason: logAuditReasonTooMany,
			Detail: fmt.Sprintf("日志文件 %d 个，超过 %d 上限，历史日志可能长期未被清理", rotated, serverLogMaxRotated),
		})
	}

	latest := filepath.Join(dir, "latest.log")
	audit.auditLatestLog(latest)
	return audit, nil
}
