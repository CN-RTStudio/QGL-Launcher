package main

import (
	"fmt"
	"strings"
)

func (audit PlayerCacheAudit) Codes() []string {
	return findingCodes(audit.Findings, func(f PlayerCacheFinding) string { return f.Reason })
}

func (audit PlayerCacheAudit) Describe() string {
	if len(audit.Findings) == 0 {
		return "玩家缓存校验通过"
	}
	parts := make([]string, 0, len(audit.Findings))
	for _, finding := range audit.Findings {
		parts = append(parts, fmt.Sprintf("#%d(%s:%s)", finding.Entry, finding.Reason, finding.Detail))
	}
	return strings.Join(parts, "；")
}
