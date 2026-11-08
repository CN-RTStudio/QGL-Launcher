package main

import (
	"fmt"
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
	return auditHasWarning(a.Findings, func(f JVMAgentFinding) bool { return !f.Blocking && f.Reason != jaReasonOK })
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
