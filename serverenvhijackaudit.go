package main

import (
	"fmt"
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
	blocking := 0
	warnings := 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != envReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("scripts=%d findings=%d blocking=%d warnings=%d", len(a.Scripts), len(a.Findings), blocking, warnings)
}
