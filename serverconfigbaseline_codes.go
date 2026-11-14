package main

import (
	"fmt"
	"strings"
)

func (a *BaselineAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodes(a.Findings, func(f BaselineFinding) string { return f.Reason })
}

func (a *BaselineAudit) Describe() string {
	if a == nil {
		return ""
	}
	if len(a.Findings) == 0 {
		return "服务器配置文件与基线一致"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s): %s", f.File, f.Reason, f.Detail))
	}
	return strings.Join(parts, "; ")
}
