package main

func describeReasonDetail(empty string, items []auditFinding, limit int) string {
	return describeAuditFindings(empty, items, limit,
		func(f auditFinding) []string { return []string{f.Reason, f.Detail} },
		func(f auditFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func describeFileReason(empty string, items []auditFinding, limit int) string {
	return describeAuditFindings(empty, items, limit,
		func(f auditFinding) []string { return []string{f.File, f.Reason} },
		func(f auditFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

func describeFileDetail(empty string, items []auditFinding, limit int) string {
	return describeAuditFindings(empty, items, limit,
		func(f auditFinding) []string { return []string{f.File, f.Detail} },
		func(f auditFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}
