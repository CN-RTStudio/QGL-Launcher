package main

import (
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
