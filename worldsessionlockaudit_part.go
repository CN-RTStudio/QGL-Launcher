package main

import (
	"fmt"
)

func (a SessionLockAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f SessionLockFinding) bool { return f.Blocking })
}

func (a SessionLockAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f SessionLockFinding) bool { return !f.Blocking && f.Reason != wslReasonOK })
}

func (a SessionLockAudit) Codes() []string {
	return findingCodesSkip(a.Findings, wslReasonOK, func(f SessionLockFinding) string { return f.Reason })
}

func (a SessionLockAudit) Describe() string {
	return describeLabeledFindings("未发现世界目录", a.Findings, 4, "",
		func(f SessionLockFinding) string { return f.World },
		func(f SessionLockFinding) string { return f.Reason })
}

func (a SessionLockAudit) Summary() string {
	blocking, warnings := 0, 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != wslReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("worlds=%d findings=%d blocking=%d warnings=%d", len(a.Worlds), len(a.Findings), blocking, warnings)
}

func (a *SessionLockAudit) add(world, reason, detail string, blocking bool) {
	if len(a.Findings) >= wslMaxFindings {
		return
	}
	a.Findings = append(a.Findings, SessionLockFinding{World: world, Reason: reason, Detail: detail, Blocking: blocking})
}
