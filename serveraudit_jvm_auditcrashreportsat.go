package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

func auditCrashReportsAt(serverDir string, now time.Time) CrashReportAudit {
	audit := CrashReportAudit{Dir: serverDir}
	root := filepath.Join(serverDir, "crash-reports")
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("", crReasonMissing, "服务器目录不存在", true)
		return audit
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		audit.add("crash-reports", crReasonOK, "未发现 crash-reports 目录", false)
		return audit
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if len(audit.Files) >= crMaxFiles {
			audit.add("crash-reports", crReasonTooMany, "崩溃报告数量超过预算", true)
			break
		}
		name := entry.Name()
		lower := strings.ToLower(name)
		rel := filepath.Join("crash-reports", name)
		if !strings.HasSuffix(lower, ".txt") && !strings.HasSuffix(lower, ".log") {
			audit.add(rel, crReasonBadName, "非预期扩展名的报告文件", false)
			continue
		}
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if err != nil {
			audit.add(rel, crReasonUnreadable, "无法读取崩溃报告", true)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(rel, crReasonSymlink, "崩溃报告是符号链接", true)
			continue
		}
		if info.Size() > crMaxFileBytes {
			audit.add(rel, crReasonTooLarge, "崩溃报告体积超过预算", true)
			continue
		}
		if info.Mode().Perm()&0o022 != 0 {
			audit.add(rel, crReasonWorldWritable, "崩溃报告可被其他用户改写", true)
		}
		if stamp, ok := crParseTimestamp(name); ok && now.Sub(stamp) > crStaleAfter {
			audit.add(rel, crReasonStale, "崩溃报告超过保留期限", false)
		}
		audit.Files = append(audit.Files, rel)
		body, err := readBoundedFile(path, crScanBytes)
		if err != nil {
			audit.add(rel, crReasonUnreadable, "无法读取报告内容", true)
			continue
		}
		crScanBody(&audit, rel, string(body))
	}
	if len(audit.Files) == 0 && len(audit.Findings) == 0 {
		audit.add("crash-reports", crReasonOK, "无崩溃报告", false)
	}
	if len(audit.Findings) == 0 {
		audit.add("", crReasonOK, "崩溃报告未发现风险", false)
	}
	return audit
}

func AuditCrashReports(serverDir string) CrashReportAudit {
	return auditCrashReportsAt(serverDir, time.Now())
}

func crRedactContext(token string) string {
	token = strings.TrimSpace(token)
	if len(token) > 24 {
		return token[:24]
	}
	return token
}
