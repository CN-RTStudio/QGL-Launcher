package main

import (
	"os"
)

func AuditServerDataPackFilters(serverDir string) PackFilterAudit {
	audit := PackFilterAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("server", "", pfReasonMissing, "服务器目录不可用", false)
		return audit
	}
	for _, root := range pfPackRoots {
		pfAuditRoot(&audit, root)
	}
	if audit.Packs == 0 {
		audit.add("datapacks", "", pfReasonOK, "未发现数据包", false)
	}
	return audit
}

func (a PackFilterAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PackFilterFinding) bool { return f.Blocking })
}
func (a PackFilterAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PackFilterFinding) bool { return !f.Blocking && f.Reason != pfReasonOK })
}
