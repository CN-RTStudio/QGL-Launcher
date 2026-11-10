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

const (
	scgMaxFindings  = 24
	scgMaxReports   = 200
	scgMaxReport    = 64 * 1024
	scgMaxTotalSize = 512 * 1024 * 1024
	scgReasonMiss   = "missing-dir"
	scgReasonLink   = "symlink-dir"
	scgReasonRead   = "unreadable"
	scgReasonMany   = "too-many-reports"
	scgReasonBig    = "report-too-large"
	scgReasonTotal  = "total-size"
	scgReasonName   = "odd-report-name"
	scgReasonSeed   = "seed-in-report"
	scgReasonToken  = "secret-in-report"
)

type CrashReportHygieneFinding = auditFinding

type CrashReportHygieneAudit struct {
	ServerDir string
	Findings  []CrashReportHygieneFinding
}

func (a *CrashReportHygieneAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, scgMaxFindings, CrashReportHygieneFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *CrashReportHygieneAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CrashReportHygieneFinding) bool { return f.Blocking })
}

func (a *CrashReportHygieneAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *CrashReportHygieneAudit) Describe() string {
	return describeReasonDetail("crash-reports 未发现风险", a.Findings, 12)
}

var scgSecretMarkers = []string{"session-token", "accessToken", "rcon.password=", "Authorization: Bearer"}

func AuditServerCrashReports(serverDir string) *CrashReportHygieneAudit {
	a := &CrashReportHygieneAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("crash-reports", scgReasonMiss, "未配置服务器目录", false)
		return a
	}
	dir := filepath.Join(serverDir, "crash-reports")
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			a.add("crash-reports", scgReasonMiss, "未找到崩溃报告目录", false)
			return a
		}
		a.add("crash-reports", scgReasonRead, err.Error(), true)
		return a
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add("crash-reports", scgReasonLink, "崩溃报告目录是符号链接", true)
		return a
	}
	if !info.IsDir() {
		a.add("crash-reports", scgReasonRead, "崩溃报告路径不是目录", true)
		return a
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add("crash-reports", scgReasonRead, err.Error(), true)
		return a
	}
	var total int64
	reports := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		reports++
		if reports > scgMaxReports {
			a.add("crash-reports", scgReasonMany, fmt.Sprintf("报告数量超过 %d", scgMaxReports), false)
			break
		}
		name := entry.Name()
		if strings.ContainsAny(name, "<>|\x00") || strings.HasPrefix(name, ".") {
			a.add(name, scgReasonName, "文件名异常", false)
		}
		full := filepath.Join(dir, name)
		link, err := isSymlinkOrSpecial(full)
		if err != nil {
			a.add(name, scgReasonRead, err.Error(), true)
			continue
		}
		if link {
			a.add(name, scgReasonLink, "报告是符号链接或特殊文件", true)
			continue
		}
		stat, err := os.Stat(full)
		if err != nil {
			a.add(name, scgReasonRead, err.Error(), true)
			continue
		}
		total += stat.Size()
		if stat.Size() > scgMaxReport {
			a.add(name, scgReasonBig, fmt.Sprintf("%d 字节", stat.Size()), false)
			continue
		}
		data, err := readBoundedFile(full, scgMaxReport)
		if err != nil {
			a.add(name, scgReasonRead, err.Error(), true)
			continue
		}
		text := string(data)
		if strings.Contains(text, "level-seed=") || strings.Contains(text, "WorldSeed") {
			a.add(name, scgReasonSeed, "报告包含世界种子", false)
		}
		for _, marker := range scgSecretMarkers {
			if strings.Contains(text, marker) {
				a.add(name, scgReasonToken, "报告包含敏感标记 "+marker, true)
				break
			}
		}
	}
	if total > scgMaxTotalSize {
		a.add("crash-reports", scgReasonTotal, fmt.Sprintf("目录合计 %d 字节", total), false)
	}
	return a
}
