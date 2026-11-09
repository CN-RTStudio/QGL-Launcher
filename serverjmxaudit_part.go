package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

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
