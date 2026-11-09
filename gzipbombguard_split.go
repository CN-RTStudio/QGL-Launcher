package main

func (m *GZBMonitor) Observe(compIn, produced int64) (safe bool, reason string) {
	if m.aborted {
		return false, m.abortReason
	}
	if compIn < 0 || produced < 0 {
		m.abort(GZBReasonNegativeDelta, "negative-delta")
		return false, m.abortReason
	}

	if produced > m.policy.MaxSingleBurstBytes {
		m.abort(GZBReasonBurstExceeded, itoaGZB64(produced))
		return false, m.abortReason
	}

	m.compressedIn += compIn
	m.producedOut += produced

	if m.producedOut > m.policy.MaxTotalBytes {
		m.abort(GZBReasonTotalExceeded, itoaGZB64(m.producedOut))
		return false, m.abortReason
	}

	// 累积压缩比（压缩输入为 0 但有产出，视为无穷膨胀，立即判高）
	if m.compressedIn > 0 {
		ratio := int(m.producedOut / m.compressedIn)
		if ratio > m.policy.MaxCompressionRatio {
			m.abort(GZBReasonRatioExceeded, itoaGZB(ratio))
			return false, m.abortReason
		}
	} else if m.producedOut > 0 {
		m.abort(GZBReasonRatioExceeded, "infinite")
		return false, m.abortReason
	}

	// 单批膨胀比连续超阈
	if compIn > 0 {
		burstRatio := int(produced / compIn)
		if burstRatio >= m.policy.SustainedRatio {
			m.highStreak++
			if m.highStreak >= m.policy.SustainedWindowStreaks {
				m.abort(GZBReasonSustainedExpansion, itoaGZB(m.highStreak))
				return false, m.abortReason
			}
		} else {
			m.highStreak = 0
		}
	}
	return true, ""
}

// Finalize 在解压结束后做声明长度一致性核对。
func (m *GZBMonitor) Finalize() (safe bool, findings []GZBFinding) {
	// 声明了压缩 Content-Length，实际产出却远超其可解释范围（>ratio*声明），记不一致
	if m.declaredLen > 0 && m.compressedIn > 0 &&
		m.producedOut > m.declaredLen*int64(m.policy.MaxCompressionRatio) {
		findings = append(findings, GZBFinding{
			Reason: GZBReasonDeclaredLengthMismatch,
			Detail: itoaGZB64(m.declaredLen) + "->" + itoaGZB64(m.producedOut)})
	}
	if m.producedOut > m.policy.MaxTotalBytes {
		findings = append(findings, GZBFinding{Reason: GZBReasonTotalExceeded})
	}
	return len(findings) == 0, findings
}
