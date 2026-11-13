package main

import (
	"fmt"
	"strings"
)

func (a *ServerFSPermAudit) Codes() []string {
	return findingCodes(a.Findings, func(f FSPermFinding) string { return f.Reason })
}

func (a *ServerFSPermAudit) Describe() string {
	if a == nil || len(a.Findings) == 0 {
		return "服务器文件权限审计: 未发现敏感路径"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == fsPermReasonOK || f.Reason == fsPermReasonMissing || f.Reason == fsPermReasonPlatform {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s(%s) %s %s", f.Path, f.Mode, f.Reason, f.Detail))
	}
	if len(parts) == 0 {
		return "服务器文件权限审计: 通过"
	}
	return strings.Join(parts, "; ")
}

func (a *ServerFSPermAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f FSPermFinding) bool { return f.Blocking }, func(f FSPermFinding) bool {
		return !f.Blocking && f.Reason != fsPermReasonOK && f.Reason != fsPermReasonMissing && f.Reason != fsPermReasonPlatform
	})
	return fmt.Sprintf("权限审计 %d 个路径，阻断 %d，告警 %d", len(a.Checked), blocking, warnings)
}

type fsPermTarget struct {
	Path       string
	Kind       string
	Secret     bool
	BlockWrite bool
	ExpectDir  bool
}
