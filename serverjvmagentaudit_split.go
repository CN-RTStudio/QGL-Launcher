package main

import (
	"fmt"
	"sort"
	"strings"
)

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
