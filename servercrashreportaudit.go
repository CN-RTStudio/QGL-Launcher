package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	crReasonOK           = "ok"
	crReasonMissing      = "missing"
	crReasonUnreadable   = "unreadable"
	crReasonSymlink      = "symlink"
	crReasonTooLarge     = "too-large"
	crReasonTooMany      = "too-many"
	crReasonBadName      = "bad-name"
	crReasonSecret       = "secret-leak"
	crReasonHomePath     = "home-path-leak"
	crReasonStale        = "stale-report"
	crReasonWorldWritable = "world-writable"

	crMaxFileBytes = 8 << 20
	crMaxFiles     = 128
	crMaxFindings  = 64
	crScanBytes    = 256 << 10
	crStaleAfter   = 30 * 24 * time.Hour
)

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

type CrashReportFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type CrashReportAudit struct {
	Dir      string
	Files    []string
	Findings []CrashReportFinding
}

func (a CrashReportAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CrashReportFinding) bool { return f.Blocking })
}

func (a CrashReportAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != crReasonOK {
			return true
		}
	}
	return false
}

func (a CrashReportAudit) Describe() string {
	var parts []string
	for _, f := range a.Findings {
		if f.Reason == crReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "crash-reports"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= crMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "崩溃报告未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *CrashReportAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= crMaxFindings {
		return
	}
	a.Findings = append(a.Findings, CrashReportFinding{
		File:     file,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
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

func crRedactContext(token string) string {
	token = strings.TrimSpace(token)
	if len(token) > 24 {
		return token[:24]
	}
	return token
}

func crParseTimestamp(name string) (time.Time, bool) {
	if !strings.HasPrefix(name, "crash-") {
		return time.Time{}, false
	}
	rest := strings.TrimPrefix(name, "crash-")
	if len(rest) < 19 {
		return time.Time{}, false
	}
	layout := "2006-01-02_15.04.05"
	stamp := rest[:19]
	parsed, err := time.ParseInLocation(layout, stamp, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
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
