package main

import (
	"os"
)

func AuditServerAdvancements(serverDir string) AdvancementAudit {
	audit := AdvancementAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("server", "", adReasonMissing, "服务器目录不可用", false)
		return audit
	}
	for _, rel := range adAdvancementDirs {
		adAuditDir(&audit, rel)
	}
	if audit.Files == 0 {
		audit.add("world/advancements", "", adReasonOK, "未发现玩家进度文件", false)
	}
	return audit
}

type AdvancementAudit struct {
	Dir      string
	Findings []AdvancementFinding
	Files    int
}

func (a AdvancementAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f AdvancementFinding) bool { return f.Blocking })
}

func (a AdvancementAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f AdvancementFinding) bool { return !f.Blocking && f.Reason != adReasonOK })
}
