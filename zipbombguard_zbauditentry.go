package main

func (a *ZBAuditor) ZBAuditEntry(e ZBEntry, streamBytes int64) (safe bool, findings []ZBFinding) {
	a.Limits.fill()
	if a.seen+1 > a.Limits.MaxEntries {
		findings = append(findings, ZBFinding{Reason: ZBReasonTooManyEntries,
			Detail: itoaGZB64(int64(a.seen + 1))})
	}
	if e.UncompressedSize > a.Limits.MaxEntryBytes {
		findings = append(findings, ZBFinding{Reason: ZBReasonEntryTooLarge,
			Detail: itoaGZB64(e.UncompressedSize)})
	}
	if zbRatioExceeds(e.CompressedSize, e.UncompressedSize, a.Limits.MaxRatio) {
		findings = append(findings, ZBFinding{Reason: ZBReasonRatioTooHigh,
			Detail: itoaGZB64(e.UncompressedSize) + "/" + itoaGZB64(e.CompressedSize)})
	}
	if a.total+e.UncompressedSize > a.Limits.MaxTotalBytes {
		findings = append(findings, ZBFinding{Reason: ZBReasonTotalTooLarge,
			Detail: itoaGZB64(a.total + e.UncompressedSize)})
	}
	if a.Limits.DiskFreeBytes > 0 &&
		a.total+e.UncompressedSize > a.Limits.DiskFreeBytes {
		findings = append(findings, ZBFinding{Reason: ZBReasonDiskBudget})
	}
	if streamBytes >= 0 && streamBytes != e.UncompressedSize {
		findings = append(findings, ZBFinding{Reason: ZBReasonDeclaredMismatch,
			Detail: itoaGZB64(e.UncompressedSize) + "!=" + itoaGZB64(streamBytes)})
	}
	if len(findings) == 0 {
		a.seen++
		a.total += e.UncompressedSize
	}
	return len(findings) == 0, findings
}

// ZBSeen 返回已接受条目数。
func (a *ZBAuditor) ZBSeen() int { return a.seen }

// ZBTotal 返回已接受解压总量。
