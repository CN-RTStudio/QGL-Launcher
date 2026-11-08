package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

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

type JVMAgentFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type JVMAgentAudit struct {
	Dir      string
	Scripts  []string
	Findings []JVMAgentFinding
}

func (a JVMAgentAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JVMAgentFinding) bool { return f.Blocking })
}

func (a JVMAgentAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != jaReasonOK {
			return true
		}
	}
	return false
}

func (a JVMAgentAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == jaReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "jvm-args"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= jaMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "JVM 启动参数未发现代理注入风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *JVMAgentAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= jaMaxFindings {
		return
	}
	a.Findings = append(a.Findings, JVMAgentFinding{
		File:     file,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
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
