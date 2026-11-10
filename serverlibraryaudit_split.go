package main

import (
	"fmt"
)

func (a LibraryAudit) Describe() string {
	return describeLabeledFindings("未发现依赖库", a.Findings, 4, "",
		func(f LibraryFinding) string { return f.File },
		func(f LibraryFinding) string { return f.Reason })
}
func (a LibraryAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f LibraryFinding) bool { return f.Blocking }, func(f LibraryFinding) bool { return !f.Blocking && f.Reason != libReasonOK })
	return fmt.Sprintf("jars=%d findings=%d blocking=%d warnings=%d", len(a.Jars), len(a.Findings), blocking, warnings)
}
