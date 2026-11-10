package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	envReasonOK         = "ok"
	envReasonMissing    = "missing"
	envReasonUnreadable = "unreadable"
	envReasonTooLarge   = "too-large"
	envReasonSymlink    = "symlink"
	envReasonPreload    = "env-preload"
	envReasonShellInit  = "env-shell-init"
	envReasonClasspath  = "env-classpath"
	envReasonJVMAgent   = "env-jvm-agent"
	envReasonJVMOptions = "env-jvm-options"
	envReasonPathHijack = "env-path-hijack"
	envReasonToolInject = "env-tool-inject"
	envReasonPythonHook = "env-python-hook"
	envMaxFileBytes     = 1 << 20
	envMaxFindings      = 96
	envMaxScripts       = 20
	envMaxInlineDetail  = 96
)

var envScriptCandidates = []string{
	"start.sh", "start.bat", "start.cmd",
	"run.sh", "run.bat", "run.cmd",
	"launch.sh", "launch.bat", "launch.cmd",
	"server.sh", "server.bat", "server.cmd",
	"env.sh", "env.bat",
}

var envDangerousNames = map[string]string{
	"LD_PRELOAD":            envReasonPreload,
	"DYLD_INSERT_LIBRARIES": envReasonPreload,
	"LD_LIBRARY_PATH":       envReasonPathHijack,
	"DYLD_LIBRARY_PATH":     envReasonPathHijack,
	"BASH_ENV":              envReasonShellInit,
	"ENV":                   envReasonShellInit,
	"CLASSPATH":             envReasonClasspath,
	"_JAVA_OPTIONS":         envReasonJVMOptions,
	"JAVA_TOOL_OPTIONS":     envReasonJVMOptions,
	"JDK_JAVA_OPTIONS":      envReasonJVMOptions,
	"MAVEN_OPTS":            envReasonToolInject,
	"GRADLE_OPTS":           envReasonToolInject,
	"ANT_OPTS":              envReasonToolInject,
	"NODE_OPTIONS":          envReasonToolInject,
	"PYTHONPATH":            envReasonPythonHook,
	"PYTHONSTARTUP":         envReasonPythonHook,
}

func (a *EnvHijackAudit) add(script, variable, reason, detail string, blocking bool) {
	if len(a.Findings) >= envMaxFindings {
		return
	}
	if len(detail) > envMaxInlineDetail {
		detail = detail[:envMaxInlineDetail] + "..."
	}
	a.Findings = append(a.Findings, EnvFinding{Script: script, Variable: variable, Reason: reason, Detail: detail, Blocking: blocking})
}
func envSplitAssignment(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	lower := strings.ToLower(line)
	for _, prefix := range []string{"export ", "set ", "setx "} {
		if strings.HasPrefix(lower, prefix) {
			line = strings.TrimSpace(line[len(prefix):])
			break
		}
	}
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "::") {
		return "", "", false
	}
	idx := strings.Index(line, "=")
	if idx <= 0 {
		return "", "", false
	}
	name := strings.TrimSpace(line[:idx])
	if name == "" || strings.ContainsAny(name, " \t\"'$") {
		return "", "", false
	}
	value := strings.TrimSpace(line[idx+1:])
	if strings.HasPrefix(value, `"`) || strings.HasPrefix(value, `'`) {
		value = strings.Trim(value, `"'`)
	}
	if value == "" {
		return "", "", false
	}
	return name, value, true
}

func envNameUpper(name string) string {
	if strings.HasPrefix(name, "%") && strings.HasSuffix(name, "%") {
		name = strings.Trim(name, "%")
	}
	return strings.ToUpper(strings.TrimSpace(name))
}

func envPathIsHijacked(value string) bool {
	lower := strings.ToLower(value)
	for _, token := range []string{"%.", ".%", "/tmp", "%temp%", "\\temp\\", ":./", ".;", "=.", "`"} {
		if strings.Contains(lower, strings.ToLower(token)) {
			return true
		}
	}
	for _, seg := range strings.Split(value, ":") {
		seg = strings.ToLower(strings.TrimSpace(seg))
		if seg == "." || seg == ".." || strings.HasPrefix(seg, "./") || strings.HasPrefix(seg, "../") {
			return true
		}
	}
	return false
}

func envValueHasAgent(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "-javaagent") || strings.Contains(lower, "-agentlib") || strings.Contains(lower, "-agentpath")
}

func envScanLine(audit *EnvHijackAudit, script, line string) {
	name, value, ok := envSplitAssignment(line)
	if !ok {
		return
	}
	upper := envNameUpper(name)
	reason, known := envDangerousNames[upper]
	if !known {
		if upper == "PATH" && envPathIsHijacked(value) {
			audit.add(script, "PATH", envReasonPathHijack, "PATH 包含当前目录或临时目录: "+value, true)
		}
		return
	}
	switch reason {
	case envReasonPreload:
		audit.add(script, upper, reason, "动态链接器预加载可注入任意代码: "+value, true)
	case envReasonShellInit:
		audit.add(script, upper, reason, "shell 启动文件被重定向，可注入任意命令", true)
	case envReasonClasspath:
		audit.add(script, upper, reason, "显式 CLASSPATH 可加载任意 jar", true)
	case envReasonJVMOptions, envReasonToolInject:
		if envValueHasAgent(value) {
			audit.add(script, upper, envReasonJVMAgent, "环境变量静默注入 java agent: "+value, true)
			return
		}
		audit.add(script, upper, reason, "环境变量会静默改变 JVM/工具链行为: "+value, false)
	case envReasonPathHijack:
		audit.add(script, upper, reason, "库搜索路径被改写，可加载任意本地库: "+value, false)
	case envReasonPythonHook:
		audit.add(script, upper, reason, "Python 启动钩子可执行任意模块: "+value, false)
	}
}

func envInspectScript(audit *EnvHijackAudit, serverDir, name string) {
	path := filepath.Join(serverDir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	audit.Scripts = append(audit.Scripts, name)
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(name, "", envReasonSymlink, "启动脚本是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(name, "", envReasonUnreadable, "启动脚本不是普通文件", true)
		return
	}
	if info.Size() > envMaxFileBytes {
		audit.add(name, "", envReasonTooLarge, "启动脚本超过大小上限", true)
		return
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		audit.add(name, "", envReasonUnreadable, "启动脚本不可读", true)
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		envScanLine(audit, name, line)
	}
}

func AuditServerEnvironmentHijack(serverDir string) EnvHijackAudit {
	audit := EnvHijackAudit{Dir: serverDir}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		audit.add("server", "", envReasonMissing, "服务器目录不存在", true)
		return audit
	}
	for i, name := range envScriptCandidates {
		if i >= envMaxScripts {
			break
		}
		envInspectScript(&audit, serverDir, name)
	}
	if len(audit.Findings) == 0 {
		audit.add("", "", envReasonOK, "启动脚本未设置可被劫持的环境变量", false)
	}
	return audit
}

type EnvFinding struct {
	Script   string
	Variable string
	Reason   string
	Detail   string
	Blocking bool
}
type EnvHijackAudit struct {
	Dir      string
	Scripts  []string
	Findings []EnvFinding
}

func (a EnvHijackAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f EnvFinding) bool { return f.Blocking })
}
func (a EnvHijackAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f EnvFinding) bool { return !f.Blocking && f.Reason != envReasonOK })
}

func (a EnvHijackAudit) Codes() []string {
	return findingCodesSkip(a.Findings, envReasonOK, func(f EnvFinding) string { return f.Reason })
}

func (a EnvHijackAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现环境变量注入"
	}
	parts := []string{}
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s:%s(%s)", f.Script, f.Variable, f.Reason))
		if len(parts) >= 6 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a EnvHijackAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f EnvFinding) bool { return f.Blocking }, func(f EnvFinding) bool { return !f.Blocking && f.Reason != envReasonOK })
	return fmt.Sprintf("scripts=%d findings=%d blocking=%d warnings=%d", len(a.Scripts), len(a.Findings), blocking, warnings)
}
