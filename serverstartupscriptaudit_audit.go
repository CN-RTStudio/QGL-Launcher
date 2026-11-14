package main

import (
	"fmt"
	"os"
	"strings"
)

func AuditServerStartupScripts(serverDir string) *ServerStartupAudit {
	audit := &ServerStartupAudit{Dir: serverDir}
	if strings.TrimSpace(serverDir) == "" {
		audit.Findings = append(audit.Findings, StartupFinding{Script: "", Reason: startupReasonMissing, Detail: "未提供服务器目录"})
		return audit
	}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.Findings = append(audit.Findings, StartupFinding{Script: "", Reason: startupReasonMissing, Detail: "服务器目录不存在"})
		return audit
	}
	for _, name := range startupScriptNames {
		auditStartupFile(audit, serverDir, name)
	}
	if len(audit.Scripts) == 0 {
		audit.Findings = append(audit.Findings, StartupFinding{Script: "", Reason: startupReasonMissing, Detail: "未找到启动脚本"})
	}
	return audit
}

func (a *ServerStartupAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f StartupFinding) bool { return f.Blocking })
}

func (a *ServerStartupAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f StartupFinding) bool {
		return !f.Blocking && f.Reason != startupReasonOK && f.Reason != startupReasonMissing
	})
}

func (a *ServerStartupAudit) Codes() []string {
	return findingCodes(a.Findings, func(f StartupFinding) string { return f.Reason })
}

func (a *ServerStartupAudit) Describe() string {
	if a == nil || len(a.Findings) == 0 {
		return "启动脚本审计: 未发现脚本"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == startupReasonOK || f.Reason == startupReasonMissing {
			continue
		}
		if f.Line > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d %s(%s)", f.Script, f.Line, f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %s(%s)", f.Script, f.Reason, f.Detail))
	}
	if len(parts) == 0 {
		return "启动脚本审计: 通过"
	}
	return strings.Join(parts, "; ")
}

func (a *ServerStartupAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f StartupFinding) bool { return f.Blocking }, func(f StartupFinding) bool {
		return !f.Blocking && f.Reason != startupReasonOK && f.Reason != startupReasonMissing
	})
	return fmt.Sprintf("启动脚本 %d 个，阻断 %d，告警 %d", len(a.Scripts), blocking, warnings)
}

func hasAnyToken(lower string, tokens ...string) bool {
	for _, t := range tokens {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}
