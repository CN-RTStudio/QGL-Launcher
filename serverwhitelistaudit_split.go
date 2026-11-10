package main

import (
	"fmt"
)

func (a WhitelistAudit) Describe() string {
	return describeLabeledFindings("未发现白名单与操作员配置", a.Findings, 6, "server",
		func(f WhitelistFinding) string { return f.File },
		func(f WhitelistFinding) string { return f.Reason })
}
func (a WhitelistAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f WhitelistFinding) bool { return f.Blocking }, func(f WhitelistFinding) bool { return !f.Blocking && f.Reason != wlReasonOK })
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}
