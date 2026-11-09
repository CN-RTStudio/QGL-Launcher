package main

func appendAuditFinding[T any](findings []T, limit int, finding T) []T {
	if len(findings) >= limit {
		return findings
	}
	return append(findings, finding)
}
