package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	crReasonOK            = "ok"
	crReasonMissing       = "missing"
	crReasonUnreadable    = "unreadable"
	crReasonSymlink       = "symlink"
	crReasonTooLarge      = "too-large"
	crReasonTooMany       = "too-many"
	crReasonBadName       = "bad-name"
	crReasonSecret        = "secret-leak"
	crReasonHomePath      = "home-path-leak"
	crReasonStale         = "stale-report"
	crReasonWorldWritable = "world-writable"

	crMaxFileBytes = 8 << 20
	crMaxFiles     = 128
	crMaxFindings  = 64
	crScanBytes    = 256 << 10
	crStaleAfter   = 30 * 24 * time.Hour
)

func (a CrashReportAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CrashReportFinding) bool { return f.Blocking })
}

func (a CrashReportAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f CrashReportFinding) bool { return !f.Blocking && f.Reason != crReasonOK })
}

func (a CrashReportAudit) Describe() string {
	return describeTaggedFindings("崩溃报告未发现风险", a.Findings, crReasonOK, "crash-reports", crMaxFindings,
		func(f CrashReportFinding) string { return f.Reason },
		func(f CrashReportFinding) string { return f.File },
		func(f CrashReportFinding) string { return f.Detail })
}

func (a *CrashReportAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, crMaxFindings, CrashReportFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func crScanBody(audit *CrashReportAudit, rel, body string) {
	lower := strings.ToLower(body)
	for _, pattern := range crSecretPatterns {
		idx := strings.Index(lower, pattern)
		if idx < 0 {
			continue
		}
		snippet := crRedactContext(lower[idx : idx+len(pattern)])
		audit.add(rel, crReasonSecret, fmt.Sprintf("疑似明文凭据: %s", snippet), true)
		break
	}
	for _, pattern := range crHomePatterns {
		if strings.Contains(lower, pattern) {
			audit.add(rel, crReasonHomePath, "报告包含用户主目录绝对路径", false)
			break
		}
	}
}

var crSecretPatterns = []string{
	"password=",
	"password:",
	"rcon.password",
	"rcon-password",
	"access_token",
	"authorization: bearer",
	"api_key",
	"apikey",
	"secret_key",
	"private_key",
	"-----begin",
	"sessionid=",
	"session_id=",
	"jdbc:mysql://",
	"mongodb://",
	"postgres://",
}
var crHomePatterns = []string{
	"/home/",
	"/root/",
	"c:\\users\\",
	"/users/",
}

type CrashReportFinding = auditFinding
type CrashReportAudit struct {
	Dir      string
	Files    []string
	Findings []CrashReportFinding
}

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
