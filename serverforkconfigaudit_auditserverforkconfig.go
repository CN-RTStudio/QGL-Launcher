package main

import (
	"os"
	"path/filepath"
	"strings"
)

func AuditServerForkConfig(serverDir string) ForkConfigAudit {
	audit := ForkConfigAudit{Dir: serverDir}
	root, err := filepath.Abs(serverDir)
	if err != nil {
		audit.add("server-dir", fkReasonUnreadable, "无法解析服务器目录", true)
		return audit
	}
	audit.Dir = root
	info, statErr := os.Lstat(root)
	if statErr != nil || !info.IsDir() {
		audit.add("server-dir", fkReasonMissing, "服务器目录不存在", true)
		return audit
	}
	found := false
	for _, name := range fkConfigFiles {
		if fkInspectFile(&audit, root, name) {
			found = true
		}
	}
	if !found {
		audit.add("fork-config", fkReasonOK, "未使用分支配置文件", false)
		return audit
	}
	if len(audit.Findings) == 0 {
		audit.add("fork-config", fkReasonOK, "分支配置未发现风险", false)
	}
	return audit
}

func (a ForkConfigAudit) Describe() string {
	return describeTaggedFindings("服务端分支配置未发现风险", a.Findings, fkReasonOK, "fork-config", fkMaxFindings,
		func(f ForkConfigFinding) string { return f.Reason },
		func(f ForkConfigFinding) string { return f.File },
		func(f ForkConfigFinding) string { return f.Detail })
}
func (a *ForkConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, fkMaxFindings, ForkConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func fkFlattenConfig(text string) map[string]string {
	props := map[string]string{}
	stackKeys := []string{}
	stackIndent := []int{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		for len(stackIndent) > 0 && indent <= stackIndent[len(stackIndent)-1] {
			stackIndent = stackIndent[:len(stackIndent)-1]
			stackKeys = stackKeys[:len(stackKeys)-1]
		}
		colon := strings.Index(trimmed, ":")
		if colon <= 0 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(trimmed[:colon]), `"'`)
		value := strings.TrimSpace(trimmed[colon+1:])
		if key == "" {
			continue
		}
		if strings.HasPrefix(value, "#") {
			continue
		}
		if value == "" {
			stackIndent = append(stackIndent, indent)
			stackKeys = append(stackKeys, strings.ToLower(key))
			continue
		}
		parts := append(append([]string{}, stackKeys...), strings.ToLower(key))
		props[strings.Join(parts, ".")] = value
	}
	return props
}
