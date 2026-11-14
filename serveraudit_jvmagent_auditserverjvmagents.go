package main

import (
	"os"
	"path/filepath"
	"strings"
)

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
