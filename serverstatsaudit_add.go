package main

func (a *StatsAudit) add(dir, file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, stMaxFindings, StatsFinding{Dir: dir, File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func stJSONDepth(data []byte) int {
	return jsonMaxDepth(data)
}

func stDuplicateKeys(data []byte) []string {
	return jsonDuplicateKeys(data)
}
