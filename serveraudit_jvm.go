package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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

const (
	jmxReasonOK               = "ok"
	jmxReasonMissing          = "missing"
	jmxReasonUnreadable       = "unreadable"
	jmxReasonTooLarge         = "too-large"
	jmxReasonSymlink          = "symlink"
	jmxReasonUnauthenticated  = "jmx-unauthenticated"
	jmxReasonNoSSL            = "jmx-no-ssl"
	jmxReasonBroadBind        = "jmx-broad-bind"
	jmxReasonInlineSecret     = "jmx-inline-secret"
	jmxReasonPasswordReadable = "jmx-password-world-readable"
	jmxReasonPasswordUnsafe   = "jmx-password-unsafe"
	jmxMaxFileBytes           = 1 << 20
	jmxMaxFindings            = 128
	jmxMaxScripts             = 32
)

var jmxScriptCandidates = []string{
	"start.sh", "start.bat", "start.cmd",
	"run.sh", "run.bat", "run.cmd",
	"launch.sh", "launch.bat", "launch.cmd",
	"server.sh", "server.bat", "server.cmd",
	"jvm.args", "user_jvm_args.txt",
}

var jmxConfigCandidates = []string{
	"management.properties",
	filepath.Join("conf", "management.properties"),
	filepath.Join("config", "management.properties"),
	filepath.Join("conf", "jmxremote.password"),
	filepath.Join("config", "jmxremote.password"),
	filepath.Join("conf", "jmxremote.access"),
}

type JMXFinding = auditFinding

func (a JMXAudit) Summary() string {
	blocking := 0
	warnings := 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != jmxReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("sources=%d findings=%d blocking=%d warnings=%d", len(a.Sources), len(a.Findings), blocking, warnings)
}

func (a *JMXAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, jmxMaxFindings, JMXFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func jmxIsLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), `"'`)
	if host == "" {
		return false
	}
	lower := strings.ToLower(host)
	switch lower {
	case "localhost", "127.0.0.1", "::1", "[::1]", "0:0:0:0:0:0:0:1":
		return true
	}
	return false
}

func jmxOptionValue(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(key):]
	rest = strings.TrimLeft(rest, "= ")
	for i := 0; i < len(rest); i++ {
		if rest[i] == ' ' || rest[i] == '\t' || rest[i] == '"' || rest[i] == '\'' || rest[i] == ';' {
			return rest[:i]
		}
	}
	return rest
}

func jmxScanLine(audit *JMXAudit, file, line string) {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "jmxremote") && !strings.Contains(lower, "java.rmi.server.hostname") && !strings.Contains(lower, "jmxremote.password") {
		return
	}
	if strings.Contains(lower, "authenticate=false") {
		audit.add(file, jmxReasonUnauthenticated, "JMX 认证被关闭，任意本地进程可读取管理接口", true)
	}
	if strings.Contains(lower, "ssl=false") {
		audit.add(file, jmxReasonNoSSL, "JMX 传输未启用 TLS，凭据与数据明文传输", true)
	}
	if strings.Contains(lower, "password=") && !strings.Contains(lower, "password.file") {
		secret := jmxOptionValue(line, "password=")
		if secret != "" {
			audit.add(file, jmxReasonInlineSecret, "JMX 口令直接写在启动参数中，会进入日志与进程列表", true)
		}
	}
	if strings.Contains(lower, "jmxremote.port=") {
		port := jmxOptionValue(line, "jmxremote.port=")
		if port != "" && port != "0" {
			audit.add(file, jmxReasonBroadBind, "启用 JMX 端口但未确认仅绑定回环地址", true)
		}
	}
	if strings.Contains(lower, "java.rmi.server.hostname=") {
		host := jmxOptionValue(line, "java.rmi.server.hostname=")
		if host != "" && !jmxIsLoopbackHost(host) {
			audit.add(file, jmxReasonBroadBind, "RMI 主机名指向非回环地址，管理端口暴露到网络", true)
		}
	}
}

func jmxKeyValue(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return "", "", false
	}
	idx := strings.Index(line, "=")
	if idx <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
}

func jmxCheckPasswordFile(audit *JMXAudit, serverDir, file string, display string) {
	path := file
	if !filepath.IsAbs(path) {
		path = filepath.Join(serverDir, path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		audit.add(display, jmxReasonMissing, "JMX 口令/权限文件不存在，运行时将退化为无认证", true)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(display, jmxReasonSymlink, "JMX 口令文件是符号链接，可被替换为攻击者控制的内容", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(display, jmxReasonPasswordUnsafe, "JMX 口令文件不是普通文件", true)
		return
	}
	if runtime.GOOS == "windows" {
		return
	}
	if info.Mode().Perm()&0o044 != 0 {
		audit.add(display, jmxReasonPasswordReadable, "JMX 口令文件对组或其他用户可读", false)
	}
	if info.Mode().Perm()&0o200 == 0 {
		audit.add(display, jmxReasonPasswordUnsafe, "JMX 口令文件不可写，运行期无法轮换", false)
	}
}

func jmxReadScript(serverDir, name string) ([]byte, string) {
	path := filepath.Join(serverDir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, jmxReasonMissing
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, jmxReasonSymlink
	}
	if !info.Mode().IsRegular() {
		return nil, jmxReasonUnreadable
	}
	if info.Size() > jmxMaxFileBytes {
		return nil, jmxReasonTooLarge
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return nil, jmxReasonUnreadable
	}
	return data, ""
}

func AuditServerJMX(serverDir string) JMXAudit {
	audit := JMXAudit{Dir: serverDir}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		audit.add("server", jmxReasonMissing, "服务器目录不存在", true)
		return audit
	}

	for i, name := range jmxScriptCandidates {
		if i >= jmxMaxScripts {
			break
		}
		data, reason := jmxReadScript(serverDir, name)
		if reason == jmxReasonMissing {
			continue
		}
		audit.Sources = append(audit.Sources, name)
		if reason != "" {
			audit.add(name, reason, "JMX 相关脚本不可用", reason == jmxReasonSymlink || reason == jmxReasonTooLarge)
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			jmxScanLine(&audit, name, line)
		}
	}

	for _, name := range jmxConfigCandidates {
		path := filepath.Join(serverDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		audit.Sources = append(audit.Sources, name)
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(name, jmxReasonSymlink, "JMX 管理配置是符号链接", true)
			continue
		}
		if !info.Mode().IsRegular() {
			audit.add(name, jmxReasonUnreadable, "JMX 管理配置不是普通文件", true)
			continue
		}
		if info.Size() > jmxMaxFileBytes {
			audit.add(name, jmxReasonTooLarge, "JMX 管理配置过大", true)
			continue
		}
		data, err := readBoundedFile(path, auditTextReadMaxBytes)
		if err != nil {
			audit.add(name, jmxReasonUnreadable, "JMX 管理配置不可读", true)
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			key, value, ok := jmxKeyValue(line)
			if !ok {
				continue
			}
			lower := strings.ToLower(key)
			switch {
			case lower == "com.sun.management.jmxremote.authenticate" && strings.EqualFold(value, "false"):
				audit.add(name, jmxReasonUnauthenticated, "管理配置文件关闭了 JMX 认证", true)
			case lower == "com.sun.management.jmxremote.ssl" && strings.EqualFold(value, "false"):
				audit.add(name, jmxReasonNoSSL, "管理配置文件关闭了 JMX TLS", true)
			case lower == "com.sun.management.jmxremote.port" && value != "" && value != "0":
				audit.add(name, jmxReasonBroadBind, "管理配置文件启用了 JMX 端口", true)
			case lower == "com.sun.management.jmxremote.password.file" && value != "":
				jmxCheckPasswordFile(&audit, serverDir, value, name)
			}
		}
	}

	if len(audit.Findings) == 0 {
		audit.add("", jmxReasonOK, "未启用 JMX 远程管理", false)
	}
	return audit
}

type JMXAudit struct {
	Dir      string
	Sources  []string
	Findings []JMXFinding
}

func (a JMXAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JMXFinding) bool { return f.Blocking })
}

func (a JMXAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f JMXFinding) bool { return !f.Blocking && f.Reason != jmxReasonOK })
}

func (a JMXAudit) Codes() []string {
	return findingCodesSkip(a.Findings, jmxReasonOK, func(f JMXFinding) string { return f.Reason })
}

func (a JMXAudit) Describe() string {
	return describeLabeledFindings("未发现 JMX 远程管理配置", a.Findings, 6, "server",
		func(f JMXFinding) string { return f.File },
		func(f JMXFinding) string { return f.Reason })
}

const (
	jaReasonOK             = "ok"
	jaReasonMissing        = "missing"
	jaReasonUnreadable     = "unreadable"
	jaReasonSymlink        = "symlink"
	jaReasonAgentOutside   = "agent-outside-server"
	jaReasonAgentTraversal = "agent-traversal"
	jaReasonAgentMissing   = "agent-not-found"
	jaReasonBootClasspath  = "bootclasspath-override"
	jaReasonDebugAgent     = "debug-agent"
	jaReasonJMXOpen        = "jmx-unauthenticated"
	jaReasonSecurityMgr    = "security-manager-allow"
	jaReasonAgentLib       = "agentlib-injected"
	jaReasonTooLarge       = "too-large"

	jaMaxScriptBytes = 1 << 20
	jaMaxScripts     = 16
	jaMaxFindings    = 48
)

var jaScriptNames = []string{
	"start.sh",
	"start.bat",
	"start.cmd",
	"run.sh",
	"run.bat",
	"run.cmd",
	"launch.sh",
	"launch.bat",
	"user_jvm_args.txt",
	"args.txt",
	"jvm.args",
}

type JVMAgentFinding = auditFinding

type JVMAgentAudit struct {
	Dir      string
	Scripts  []string
	Findings []JVMAgentFinding
}

func (a JVMAgentAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JVMAgentFinding) bool { return f.Blocking })
}

func (a JVMAgentAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f JVMAgentFinding) bool { return !f.Blocking && f.Reason != jaReasonOK })
}

func jaAgentPath(token string) (string, bool) {
	for _, prefix := range []string{"-javaagent:", "-agentpath:"} {
		if strings.HasPrefix(token, prefix) {
			value := strings.TrimPrefix(token, prefix)
			if idx := strings.Index(value, "="); idx >= 0 {
				value = value[:idx]
			}
			return value, true
		}
	}
	return "", false
}
func jaCheckAgentPath(a *JVMAgentAudit, file, raw string) {
	path := strings.TrimSpace(strings.Trim(raw, `"`))
	if path == "" {
		a.add(file, jaReasonAgentMissing, "代理参数缺少路径", true)
		return
	}
	if strings.Contains(path, "..") {
		a.add(file, jaReasonAgentTraversal, "代理路径包含上级目录引用", true)
		return
	}
	resolved := path
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(a.Dir, resolved)
	}
	absDir, errDir := filepath.Abs(a.Dir)
	absFile, errFile := filepath.Abs(resolved)
	if errDir == nil && errFile == nil {
		rel, err := filepath.Rel(absDir, absFile)
		if err == nil && (rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			a.add(file, jaReasonAgentOutside, "代理 jar 位于服务器目录之外", true)
			return
		}
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		a.add(file, jaReasonAgentMissing, "代理 jar 不存在", false)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(file, jaReasonSymlink, "代理 jar 是符号链接", true)
	}
}

func jaInspectLine(a *JVMAgentAudit, file, line string) {
	for _, token := range jaSplitTokens(line) {
		if strings.HasPrefix(token, "#") {
			return
		}
		if path, ok := jaAgentPath(token); ok {
			jaCheckAgentPath(a, file, path)
			continue
		}
		lower := strings.ToLower(token)
		switch {
		case strings.HasPrefix(token, "-agentlib:"):
			value := strings.TrimPrefix(token, "-agentlib:")
			if strings.HasPrefix(strings.ToLower(value), "jdwp") {
				a.add(file, jaReasonDebugAgent, "开启 JDWP 调试代理", true)
				if strings.Contains(strings.ToLower(value), "address=*") ||
					strings.Contains(strings.ToLower(value), "address=0.0.0.0") {
					a.add(file, jaReasonDebugAgent, "调试代理监听全部接口", true)
				}
				continue
			}
			a.add(file, jaReasonAgentLib, "使用 agentlib 加载本地代理", false)
		case strings.HasPrefix(lower, "-xbootclasspath"):
			a.add(file, jaReasonBootClasspath, "覆盖引导类路径", true)
		case strings.HasPrefix(lower, "-djava.security.manager=allow"):
			a.add(file, jaReasonSecurityMgr, "允许运行时安装安全管理器", false)
		case strings.HasPrefix(lower, "-dcom.sun.management.jmxremote.authenticate=false"):
			a.add(file, jaReasonJMXOpen, "JMX 关闭认证", true)
		case strings.HasPrefix(lower, "-dcom.sun.management.jmxremote.port="):
			a.add(file, jaReasonJMXOpen, "开放 JMX 远程端口", false)
		}
	}
}

func jaInspectScript(a *JVMAgentAudit, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	rel, relErr := filepath.Rel(a.Dir, path)
	if relErr != nil {
		rel = filepath.Base(path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(rel, jaReasonSymlink, "启动脚本是符号链接", true)
		return
	}
	if info.Size() > jaMaxScriptBytes {
		a.add(rel, jaReasonTooLarge, "启动脚本超过体积预算", true)
		return
	}
	data, err := readBoundedFile(path, jaMaxScriptBytes)
	if err != nil {
		a.add(rel, jaReasonUnreadable, "启动脚本不可读", true)
		return
	}
	a.Scripts = append(a.Scripts, rel)
	for _, line := range strings.Split(string(data), "\n") {
		jaInspectLine(a, rel, strings.TrimSpace(line))
	}
}

func AuditServerJVMAgents(serverDir string) JVMAgentAudit {
	audit := JVMAgentAudit{Dir: serverDir}
	found := 0
	for _, name := range jaScriptNames {
		path := filepath.Join(serverDir, name)
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		if found >= jaMaxScripts {
			break
		}
		found++
		jaInspectScript(&audit, path)
	}
	if found == 0 {
		audit.add("jvm-args", jaReasonMissing, "未找到启动脚本或 JVM 参数文件", false)
	}
	if len(audit.Findings) == 0 {
		audit.add("jvm-args", jaReasonOK, "启动参数未包含代理注入", false)
	}
	return audit
}

func (a JVMAgentAudit) Describe() string {
	return describeTaggedFindings("JVM 启动参数未发现代理注入风险", a.Findings, jaReasonOK, "jvm-args", jaMaxFindings,
		func(f JVMAgentFinding) string { return f.Reason },
		func(f JVMAgentFinding) string { return f.File },
		func(f JVMAgentFinding) string { return f.Detail })
}
func (a *JVMAgentAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, jaMaxFindings, JVMAgentFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func jaSplitTokens(line string) []string {
	tokens := []string{}
	var current strings.Builder
	quote := rune(0)
	for _, r := range line {
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			current.WriteRune(r)
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == ' ' || r == '\t' || r == '\r' {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

const (
	sjaMaxFindings  = 28
	sjaMaxFile      = 64 * 1024
	sjaMaxHeapGB    = 32
	sjaReasonMiss   = "missing"
	sjaReasonLink   = "symlink"
	sjaReasonLarge  = "too-large"
	sjaReasonRead   = "unreadable"
	sjaReasonAgent  = "java-agent"
	sjaReasonBoot   = "bootclasspath"
	sjaReasonExec   = "on-error-command"
	sjaReasonArg    = "argfile-indirection"
	sjaReasonHeap   = "heap-too-large"
	sjaReasonPolicy = "security-manager"
	sjaReasonQuote  = "unbalanced-quote"
	sjaReasonCTRL   = "control-characters"
	sjaReasonJMX    = "jmx-exposed"
)

type JvmArgsFinding = auditFinding
type JvmArgsAudit struct {
	ServerDir string
	Findings  []JvmArgsFinding
}

func (a *JvmArgsAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sjaMaxFindings, JvmArgsFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *JvmArgsAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JvmArgsFinding) bool { return f.Blocking })
}

func (a *JvmArgsAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *JvmArgsAudit) Describe() string {
	return describeReasonDetail("user_jvm_args.txt 未发现风险", a.Findings, 12)
}

func sjaHeapGB(value string) (float64, bool) {
	upper := strings.ToUpper(strings.TrimSpace(value))
	mul := float64(1)
	switch {
	case strings.HasSuffix(upper, "G"):
		mul = 1
	case strings.HasSuffix(upper, "M"):
		mul = 1.0 / 1024.0
	case strings.HasSuffix(upper, "K"):
		mul = 1.0 / (1024.0 * 1024.0)
	default:
		return 0, false
	}
	number := strings.TrimSpace(upper[:len(upper)-1])
	v, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0, false
	}
	return v * mul, true
}

func AuditServerJvmArgsFile(serverDir string) *JvmArgsAudit {
	a := &JvmArgsAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("user_jvm_args.txt", sjaReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "user_jvm_args.txt"
	path := filepath.Join(serverDir, rel)
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, sjaReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, sjaReasonLink, "JVM 参数文件是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, sjaReasonMiss, "未找到 user_jvm_args.txt", false)
		return a
	}
	data, err := readBoundedFile(path, sjaMaxFile)
	if err != nil {
		reason := sjaReasonRead
		if err == errLocalFileTooLarge {
			reason = sjaReasonLarge
		}
		a.add(rel, reason, err.Error(), true)
		return a
	}
	text := string(data)
	tokens := strings.Fields(strings.ReplaceAll(text, "\r\n", "\n"))
	quoteOpen := false
	for _, token := range tokens {
		if strings.HasPrefix(token, "#") {
			continue
		}
		if strings.Count(token, "\"")%2 == 1 {
			quoteOpen = !quoteOpen
		}
		lower := strings.ToLower(token)
		switch {
		case strings.HasPrefix(lower, "-javaagent:"):
			a.add(rel, sjaReasonAgent, token, true)
		case strings.HasPrefix(lower, "-agentlib:"):
			a.add(rel, sjaReasonAgent, token, true)
		case strings.HasPrefix(lower, "-agentpath:"):
			a.add(rel, sjaReasonAgent, token, true)
		case strings.HasPrefix(lower, "-xbootclasspath"):
			a.add(rel, sjaReasonBoot, token, true)
		case strings.HasPrefix(lower, "-xx:onerror"), strings.HasPrefix(lower, "-xx:onoutofmemoryerror"):
			a.add(rel, sjaReasonExec, token, true)
		case strings.HasPrefix(lower, "@"):
			a.add(rel, sjaReasonArg, token, true)
		case strings.Contains(lower, "java.security.manager=allow"):
			a.add(rel, sjaReasonPolicy, token, false)
		case strings.Contains(lower, "com.sun.management.jmxremote"):
			if !strings.Contains(lower, "authenticate=true") && !strings.Contains(lower, "ssl=true") {
				a.add(rel, sjaReasonJMX, token, false)
			}
		case strings.HasPrefix(lower, "-xmx") || strings.HasPrefix(lower, "-xms"):
			if gb, ok := sjaHeapGB(token[4:]); ok && gb > sjaMaxHeapGB {
				a.add(rel, sjaReasonHeap, token, false)
			}
		}
		if cfgHasControlChars(token) {
			a.add(rel, sjaReasonCTRL, "参数含控制字符", true)
		}
	}
	if quoteOpen {
		a.add(rel, sjaReasonQuote, "引号未闭合", true)
	}
	return a
}

const (
	ljMaxFindings      = 48
	ljMaxConfig        = 512 * 1024
	ljMaxJarName       = 128
	ljVulnVersion      = "2.17.0"
	ljReasonOK         = "ok"
	ljReasonMissing    = "missing"
	ljReasonVulnerable = "vulnerable-log4j"
	ljReasonJndiLookup = "jndi-lookup"
	ljReasonPattern    = "forced-lookup-pattern"
	ljReasonBadConfig  = "bad-config"
	ljReasonSymlink    = "symlink"
	ljReasonTooLarge   = "too-large"
	ljReasonBadName    = "bad-jar-name"
)

type Log4jFinding = auditFinding
type Log4jShellAudit struct {
	ServerDir string
	Jars      int
	Configs   int
	Findings  []Log4jFinding
}

func (a *Log4jShellAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, ljMaxFindings, Log4jFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *Log4jShellAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f Log4jFinding) bool { return f.Blocking })
}
func (a *Log4jShellAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f Log4jFinding) bool { return f.Reason != ljReasonOK && !f.Blocking })
}
func (a *Log4jShellAudit) Describe() string {
	return describeFindings(a.Findings, func(f Log4jFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func ljStripJarName(name string) (string, string) {
	base := strings.ToLower(filepath.Base(name))
	if !strings.HasSuffix(base, ".jar") {
		return "", ""
	}
	base = strings.TrimSuffix(base, ".jar")
	if !strings.HasPrefix(base, "log4j-core-") {
		return "", ""
	}
	version := strings.TrimPrefix(base, "log4j-core-")
	if version == "" {
		return "", ""
	}
	return base, version
}

func ljParseVersion(raw string) (int, int, int, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return 0, 0, 0, false
	}
	nums := make([]int, 0, 3)
	for i := 0; i < 3 && i < len(parts); i++ {
		chunk := parts[i]
		if i == 2 {
			idx := strings.IndexAny(chunk, "-+")
			if idx >= 0 {
				chunk = chunk[:idx]
			}
			if chunk == "" {
				chunk = "0"
			}
		}
		n, err := strconv.Atoi(chunk)
		if err != nil || n < 0 {
			return 0, 0, 0, false
		}
		nums = append(nums, n)
	}
	for len(nums) < 3 {
		nums = append(nums, 0)
	}
	return nums[0], nums[1], nums[2], true
}

func ljVersionVulnerable(major, minor int) bool {
	if major != 2 {
		return major == 1
	}
	return minor < 17
}

func ljScanJarDir(root, rel string, a *Log4jShellAudit) {
	dir := filepath.Join(root, rel)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return
	}
	_ = filepath.Walk(dir, func(path string, fi os.FileInfo, werr error) error {
		if werr != nil {
			return nil
		}
		if fi.IsDir() {
			return nil
		}
		relPath, rerr := filepath.Rel(root, path)
		if rerr != nil {
			relPath = path
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			a.add(relPath, ljReasonSymlink, "日志组件路径为符号链接", true)
			return nil
		}
		if len(filepath.Base(path)) > ljMaxJarName {
			a.add(relPath, ljReasonBadName, "文件名超长", false)
			return nil
		}
		base, version := ljStripJarName(path)
		if base == "" {
			return nil
		}
		a.Jars++
		major, minor, patch, ok := ljParseVersion(version)
		if !ok {
			a.add(relPath, ljReasonBadName, "版本号无法解析: "+version, false)
			return nil
		}
		if ljVersionVulnerable(major, minor) {
			a.add(relPath, ljReasonVulnerable, fmt.Sprintf("log4j-core %d.%d.%d 低于 %s", major, minor, patch, ljVulnVersion), true)
		}
		return nil
	})
}

func ljScanConfig(root string, a *Log4jShellAudit) {
	for _, rel := range []string{"log4j2.xml", "config/log4j2.xml"} {
		path := filepath.Join(root, rel)
		sym, serr := isSymlinkOrSpecial(path)
		if serr == nil && sym {
			a.add(rel, ljReasonSymlink, "配置文件为符号链接或特殊文件", true)
			continue
		}
		data, err := readBoundedFile(path, ljMaxConfig)
		if err != nil {
			if _, serr := os.Lstat(path); serr == nil {
				if strings.Contains(err.Error(), "too large") {
					a.add(rel, ljReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", ljMaxConfig), true)
				}
			}
			continue
		}
		a.Configs++
		text := strings.ToLower(string(data))
		if !strings.Contains(text, "log4j") && !strings.Contains(text, "appenders") {
			a.add(rel, ljReasonBadConfig, "内容不像 log4j2 配置", false)
			continue
		}
		if strings.Contains(text, "${jndi:") || strings.Contains(text, "%{jndi:") {
			a.add(rel, ljReasonJndiLookup, "配置中出现 JNDI 查找表达式", true)
		}
		if strings.Contains(text, "${ctx:") || strings.Contains(text, "$${") {
			a.add(rel, ljReasonPattern, "配置中出现强制查找占位符", false)
		}
		if strings.Contains(text, "<lookup") || strings.Contains(text, "lookups=") {
			a.add(rel, ljReasonPattern, "配置显式声明 lookup 扩展", true)
		}
	}
}

func AuditServerLog4jShell(serverDir string) *Log4jShellAudit {
	a := &Log4jShellAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", ljReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", ljReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", ljReasonMissing, "服务器目录不存在", false)
		return a
	}
	ljScanJarDir(serverDir, "libraries", a)
	ljScanJarDir(serverDir, "plugins", a)
	ljScanConfig(serverDir, a)
	if a.Jars == 0 && a.Configs == 0 {
		a.add(".", ljReasonMissing, "未发现 log4j 组件与配置", false)
	}
	return a
}

const (
	logAuditReasonSymlink       = "symlink"
	logAuditReasonNotRegular    = "not-regular"
	logAuditReasonTooLarge      = "too-large"
	logAuditReasonBadName       = "bad-name"
	logAuditReasonTooMany       = "too-many"
	logAuditReasonUnreadable    = "unreadable"
	logAuditReasonWorldWritable = "world-writable"
	logAuditReasonExploitMark   = "exploit-attempt"
	logAuditReasonScanTooLarge  = "scan-too-large"

	serverLogMaxEntries   = 512
	serverLogMaxRotated   = 64
	serverLogMaxFileBytes = 32 << 20
	serverLogScanBytes    = 8 << 20
	serverLogMaxNameRunes = 128
)

var logExploitMarkers = []string{
	"${jndi:",
	"ldap://",
	"ldaps://",
	"rmi://",
	"dns://",
	"${lower:",
	"${upper:",
	"${env:",
}

type LogFinding struct {
	Name     string
	Reason   string
	Detail   string
	Blocking bool
}
type ServerLogAudit struct {
	Dir      string
	Present  bool
	Entries  int
	Findings []LogFinding
}

func (a *ServerLogAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f LogFinding) bool { return f.Blocking })
}

func (a *ServerLogAudit) HasWarnings() bool {
	if a == nil {
		return false
	}
	for _, f := range a.Findings {
		if !f.Blocking {
			return true
		}
	}
	return false
}
func (a *ServerLogAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodes(a.Findings, func(f LogFinding) string { return f.Reason })
}
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

func (a *ServerLogAudit) auditLogEntry(dir string, entry os.DirEntry) {
	name := entry.Name()
	if len([]rune(name)) > serverLogMaxNameRunes || containsControlByte(name) {
		a.Findings = append(a.Findings, LogFinding{
			Name: name, Reason: logAuditReasonBadName, Detail: "日志文件名含控制字符或超长",
		})
	}
	info, err := os.Lstat(filepath.Join(dir, name))
	if err != nil {
		a.Findings = append(a.Findings, LogFinding{
			Name: name, Reason: logAuditReasonUnreadable, Detail: "无法读取日志文件属性",
		})
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.Findings = append(a.Findings, LogFinding{
			Name: name, Reason: logAuditReasonSymlink,
			Detail: "日志文件是符号链接，写入会落到服务器目录之外", Blocking: true,
		})
		return
	}
	if !info.Mode().IsRegular() {
		a.Findings = append(a.Findings, LogFinding{
			Name: name, Reason: logAuditReasonNotRegular, Detail: "日志条目不是普通文件", Blocking: true,
		})
		return
	}
	if info.Size() > serverLogMaxFileBytes {
		a.Findings = append(a.Findings, LogFinding{
			Name: name, Reason: logAuditReasonTooLarge,
			Detail: fmt.Sprintf("日志大小 %d 字节，超过 %d 上限", info.Size(), serverLogMaxFileBytes),
		})
	}
}

func (a *ServerLogAudit) auditLatestLog(path string) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	if info.Size() > serverLogMaxFileBytes {
		return
	}
	if info.Size() > serverLogScanBytes {
		a.Findings = append(a.Findings, LogFinding{
			Name: "latest.log", Reason: logAuditReasonScanTooLarge,
			Detail: fmt.Sprintf("latest.log 大小 %d 字节，仅扫描前 %d 字节", info.Size(), serverLogScanBytes),
		})
	}
	data, err := readLogHead(path, serverLogScanBytes)
	if err != nil {
		return
	}
	lower := bytes.ToLower(data)
	for _, marker := range logExploitMarkers {
		if !bytes.Contains(lower, []byte(marker)) {
			continue
		}
		line := findLogLineWithMarker(data, marker)
		detail := fmt.Sprintf("latest.log 含 %q 利用特征（可能是 Log4Shell/JNDI 注入尝试）", marker)
		if line != "" {
			detail = fmt.Sprintf("%s，首个命中行: %s", detail, line)
		}
		a.Findings = append(a.Findings, LogFinding{
			Name: "latest.log", Reason: logAuditReasonExploitMark, Detail: detail,
		})
	}
}

func readLogHead(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, int64(limit)))
}

func findLogLineWithMarker(data []byte, marker string) string {
	lines := bytes.Split(data, []byte("\n"))
	for _, raw := range lines {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		if strings.Contains(strings.ToLower(line), marker) {
			return truncateLogLine(line, 160)
		}
	}
	return ""
}

func truncateLogLine(line string, max int) string {
	if len([]rune(line)) <= max {
		return line
	}
	runes := []rune(line)
	return string(runes[:max]) + "..."
}

const (
	lgReasonOK             = "ok"
	lgReasonMissing        = "missing"
	lgReasonUnreadable     = "unreadable"
	lgReasonSymlink        = "symlink"
	lgReasonTooLarge       = "too-large"
	lgReasonJNDILookup     = "jndi-lookup"
	lgReasonEnvLookup      = "env-lookup"
	lgReasonPlainSecret    = "plaintext-secret"
	lgReasonWorldWritable  = "world-writable"
	lgReasonWorldReadable  = "world-readable"
	lgReasonRemoteAppender = "remote-appender"
	lgReasonJDBCTarget     = "jdbc-target"
	lgReasonLogSymlink     = "log-symlink"
	lgReasonLogRotate      = "log-rotate-missing"
	lgReasonLogVolume      = "log-volume"

	lgMaxConfigBytes = 2 << 20
	lgMaxLogBytes    = 256 << 20
	lgMaxLogFiles    = 64
	lgMaxFindings    = 64
)

var lgConfigCandidates = []string{
	"log4j2.xml",
	"log4j2-server.xml",
	"config/log4j2.xml",
	"logback.xml",
	"config/logback.xml",
	"logging.properties",
}

var lgSecretPatterns = []string{
	"password=",
	"password:",
	"<password>",
	"passwd=",
	"secret=",
	"accesskey",
	"secretkey",
	"apikey",
	"api_key",
}

var lgJNDITokens = []string{
	"${jndi:",
	"${jndi ",
	"jndilookup",
	"initialcontext",
}
var lgLookupTokens = []string{
	"${env:",
	"${sys:",
	"${ctx:",
	"${docker:",
	"${k8s:",
	"${date:",
	"${java:",
	"${lower:",
	"${upper:",
}

type LogConfigFinding = auditFinding
type LogConfigAudit struct {
	Dir      string
	Files    []string
	Findings []LogConfigFinding
}

func (a LogConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f LogConfigFinding) bool { return f.Blocking })
}
func (a LogConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f LogConfigFinding) bool { return !f.Blocking && f.Reason != lgReasonOK })
}

func (a LogConfigAudit) Describe() string {
	return describeTaggedFindings("服务端日志配置未发现风险", a.Findings, lgReasonOK, "log-config", lgMaxFindings,
		func(f LogConfigFinding) string { return f.Reason },
		func(f LogConfigFinding) string { return f.File },
		func(f LogConfigFinding) string { return f.Detail })
}
func (a *LogConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, lgMaxFindings, LogConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func lgScanConfigText(text string) (jndi, lookup, secret, remote, jdbc bool) {
	lower := strings.ToLower(text)
	for _, token := range lgJNDITokens {
		if strings.Contains(lower, token) {
			jndi = true
			break
		}
	}
	for _, token := range lgLookupTokens {
		if strings.Contains(lower, token) {
			lookup = true
			break
		}
	}
	for _, token := range lgSecretPatterns {
		if strings.Contains(lower, token) {
			secret = true
			break
		}
	}
	if strings.Contains(lower, "<socket") || strings.Contains(lower, "<jms") ||
		strings.Contains(lower, "syslog") || strings.Contains(lower, "httpappender") {
		remote = true
	}
	if strings.Contains(lower, "jdbc:") || strings.Contains(lower, "jdbcappender") {
		jdbc = true
	}
	return
}

func lgInspectConfig(a *LogConfigAudit, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	rel, relErr := filepath.Rel(a.Dir, path)
	if relErr != nil {
		rel = filepath.Base(path)
	}
	a.Files = append(a.Files, rel)
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(rel, lgReasonSymlink, "日志配置是符号链接", true)
		return
	}
	if info.Size() > lgMaxConfigBytes {
		a.add(rel, lgReasonTooLarge, "日志配置超过体积预算", true)
		return
	}
	if info.Mode().Perm()&0o022 != 0 {
		a.add(rel, lgReasonWorldWritable, "日志配置可被其他用户改写", true)
	}
	data, err := readBoundedFile(path, lgMaxConfigBytes)
	if err != nil {
		a.add(rel, lgReasonUnreadable, "日志配置不可读", true)
		return
	}
	jndi, lookup, secret, remote, jdbc := lgScanConfigText(string(data))
	if jndi {
		a.add(rel, lgReasonJNDILookup, "日志配置包含 JNDI 查找表达式", true)
	}
	if lookup {
		a.add(rel, lgReasonEnvLookup, "日志配置使用运行时属性查找", false)
	}
	if secret {
		a.add(rel, lgReasonPlainSecret, "日志配置内写了明文口令", true)
	}
	if remote {
		a.add(rel, lgReasonRemoteAppender, "日志配置存在远程 appender", true)
	}
	if jdbc {
		a.add(rel, lgReasonJDBCTarget, "日志配置直连数据库写入", false)
	}
}

func lgInspectLogDir(a *LogConfigAudit, dir string) {
	info, err := os.Lstat(dir)
	if err != nil {
		return
	}
	rel, relErr := filepath.Rel(a.Dir, dir)
	if relErr != nil {
		rel = "logs"
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(rel, lgReasonLogSymlink, "日志目录是符号链接", true)
		return
	}
	if !info.IsDir() {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add(rel, lgReasonUnreadable, "日志目录不可读", false)
		return
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		count++
		if count > lgMaxLogFiles {
			a.add(rel, lgReasonLogVolume, "日志目录文件数量超过预算", false)
			break
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		relFile := filepath.Join(rel, entry.Name())
		if info.Mode()&os.ModeSymlink != 0 {
			a.add(relFile, lgReasonSymlink, "日志文件是符号链接", true)
			continue
		}
		if info.Size() > lgMaxLogBytes {
			a.add(relFile, lgReasonTooLarge, "单个日志文件超过体积预算", false)
		}
		if info.Mode().Perm()&0o004 != 0 {
			a.add(relFile, lgReasonWorldReadable, "日志文件对其他用户可读", false)
		}
	}
	if count > 1 && !strings.Contains(strings.ToLower(strings.Join(lgFileNames(entries), ",")), ".gz") {
		a.add(rel, lgReasonLogRotate, "历史日志未压缩或未轮转", false)
	}
}

func lgFileNames(entries []os.DirEntry) []string {
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func AuditServerLogConfig(serverDir string) LogConfigAudit {
	audit := LogConfigAudit{Dir: serverDir}
	found := 0
	for _, rel := range lgConfigCandidates {
		path := filepath.Join(serverDir, rel)
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		found++
		lgInspectConfig(&audit, path)
	}
	if found == 0 {
		audit.add("log-config", lgReasonMissing, "未使用外部日志配置文件", false)
	}
	lgInspectLogDir(&audit, filepath.Join(serverDir, "logs"))
	if len(audit.Findings) == 0 {
		audit.add("log-config", lgReasonOK, "日志配置与日志目录符合预期", false)
	}
	return audit
}

const (
	spwMaxFindings      = 40
	spwMaxProps         = 256 * 1024
	spwMaxYAML          = 512 * 1024
	spwMinTimeout       = 60
	spwMaxTimeout       = 900
	spwReasonOK         = "ok"
	spwReasonMissing    = "missing"
	spwReasonSymlink    = "symlink"
	spwReasonTooLarge   = "too-large"
	spwReasonUnreadable = "unreadable"
	spwReasonDisabled   = "watchdog-disabled"
	spwReasonLow        = "watchdog-timeout-low"
	spwReasonHigh       = "watchdog-timeout-high"
	spwReasonBadValue   = "bad-value"
	spwReasonNoScript   = "restart-script-missing"
	spwReasonAbsPath    = "restart-script-absolute-path"
	spwReasonTraversal  = "restart-script-traversal"
	spwReasonMeta       = "restart-script-metacharacters"
	spwReasonEarlyOff   = "early-warning-disabled"
	spwReasonEarlyBad   = "early-warning-invalid"
	spwReasonRestartOff = "restart-on-crash-disabled"
)

type WatchdogFinding = auditFinding
type WatchdogAudit struct {
	ServerDir string
	Findings  []WatchdogFinding
}

func (a *WatchdogAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spwMaxFindings, WatchdogFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *WatchdogAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WatchdogFinding) bool { return f.Blocking })
}

func (a *WatchdogAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WatchdogAudit) Describe() string {
	return describeFileReason("看门狗与重启配置未发现风险", a.Findings, 12)
}

func spwLoadText(a *WatchdogAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func spwBool(flat map[string]string, path string) (bool, bool) {
	return flatBoolValue(flat, path)
}

func spwText(flat map[string]string, path string) (string, bool) {
	value, ok := cfgLookup(flat, path)
	if !ok {
		return "", false
	}
	return cfgStripQuotes(value), true
}

func spwScriptProblem(script string) (string, string) {
	trimmed := strings.TrimSpace(script)
	if trimmed == "" {
		return spwReasonNoScript, "restart-script 为空"
	}
	if strings.ContainsRune(trimmed, 0) || cfgHasControlChars(trimmed) {
		return spwReasonMeta, "restart-script 含控制字符"
	}
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "\\") || strings.Contains(trimmed, ":\\") {
		return spwReasonAbsPath, "restart-script 使用绝对路径"
	}
	if strings.Contains(trimmed, "..") {
		return spwReasonTraversal, "restart-script 含目录穿越片段"
	}
	if strings.ContainsAny(trimmed, ";&|`$><\n") {
		return spwReasonMeta, "restart-script 含 shell 元字符"
	}
	return "", ""
}

func AuditServerWatchdog(serverDir string) *WatchdogAudit {
	a := &WatchdogAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", spwReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", spwReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", spwReasonMissing, "服务器目录不存在", false)
		return a
	}

	if text, ok := spwLoadText(a, serverDir, "server.properties", spwMaxProps); ok {
		props := pxParseProperties(text)
		if raw, found := props["max-tick-time"]; found {
			if value, parsed := cfgParseInt(strings.TrimSpace(raw)); parsed {
				if value < 0 {
					a.add("server.properties", spwReasonDisabled, "max-tick-time<0 关闭看门狗", false)
				} else if value == 0 {
					a.add("server.properties", spwReasonBadValue, "max-tick-time=0", true)
				} else if value > spwMaxTimeout*1000 {
					a.add("server.properties", spwReasonHigh, "max-tick-time 过大", false)
				}
			} else {
				a.add("server.properties", spwReasonBadValue, "max-tick-time 非整数", true)
			}
		}
	}

	restartOnCrash := false
	restartScript := ""
	if text, ok := spwLoadText(a, serverDir, "spigot.yml", spwMaxYAML); ok {
		flat := cfgFlattenYAML(text)
		if value, found := spwBool(flat, "settings.restart-on-crash"); found {
			restartOnCrash = value
			if !value {
				a.add("spigot.yml", spwReasonRestartOff, "restart-on-crash 已关闭", false)
			}
		}
		if timeoutText, found := spwText(flat, "settings.timeout-time"); found {
			if timeout, parsed := cfgParseInt(timeoutText); !parsed {
				a.add("spigot.yml", spwReasonBadValue, "timeout-time 非整数", true)
			} else if timeout < spwMinTimeout {
				a.add("spigot.yml", spwReasonLow, fmt.Sprintf("timeout-time=%d 过低", timeout), false)
			} else if timeout > spwMaxTimeout {
				a.add("spigot.yml", spwReasonHigh, fmt.Sprintf("timeout-time=%d 过高", timeout), false)
			}
		}
		if script, found := spwText(flat, "settings.restart-script"); found {
			restartScript = script
		}
	}

	if restartOnCrash {
		if reason, detail := spwScriptProblem(restartScript); reason != "" {
			blocking := reason != spwReasonRestartOff
			a.add("spigot.yml", reason, detail, blocking)
		}
	}

	if text, ok := spwLoadText(a, serverDir, "config/paper-global.yml", spwMaxYAML); ok {
		flat := cfgFlattenYAML(text)
		if everyText, found := spwText(flat, "watchdog.early-warning-every"); found {
			if every, parsed := cfgParseInt(everyText); !parsed {
				a.add("config/paper-global.yml", spwReasonEarlyBad, "early-warning-every 非整数", true)
			} else if every < 0 {
				a.add("config/paper-global.yml", spwReasonEarlyBad, "early-warning-every 为负值", true)
			} else if every == 0 {
				a.add("config/paper-global.yml", spwReasonEarlyOff, "early-warning-every 已关闭", false)
			}
		}
		if delayText, found := spwText(flat, "watchdog.early-warning-delay"); found {
			if delay, parsed := cfgParseInt(delayText); !parsed || delay < 0 {
				a.add("config/paper-global.yml", spwReasonEarlyBad, "early-warning-delay 非法", true)
			}
		}
	}
	return a
}
