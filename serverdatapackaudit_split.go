package main

import (
	"fmt"
)

func (a DataPackAudit) Describe() string {
	return describeLabeledFindings("未发现数据包", a.Findings, 6, "server",
		func(f DataPackFinding) string { return f.File },
		func(f DataPackFinding) string { return f.Reason })
}
func (a DataPackAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f DataPackFinding) bool { return f.Blocking }, func(f DataPackFinding) bool { return !f.Blocking && f.Reason != dpReasonOK })
	return fmt.Sprintf("packs=%d findings=%d blocking=%d warnings=%d", len(a.Packs), len(a.Findings), blocking, warnings)
}
