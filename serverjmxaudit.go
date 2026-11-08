package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

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

type JMXFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
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
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != jmxReasonOK {
			return true
		}
	}
	return false
}

func (a JMXAudit) Codes() []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, f := range a.Findings {
		if f.Reason == jmxReasonOK || seen[f.Reason] {
			continue
		}
		seen[f.Reason] = true
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}

func (a JMXAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现 JMX 远程管理配置"
	}
	parts := []string{}
	for _, f := range a.Findings {
		where := f.File
		if where == "" {
			where = "server"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", where, f.Reason))
		if len(parts) >= 6 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

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
	if len(a.Findings) >= jmxMaxFindings {
		return
	}
	a.Findings = append(a.Findings, JMXFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
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
