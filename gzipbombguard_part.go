package main

type GZBMonitor struct {
	policy       GZBPolicy
	compressedIn int64
	producedOut  int64
	highStreak   int
	declaredLen  int64 // 响应头里的压缩 Content-Length，0 表示未知
	aborted      bool
	abortReason  string
}

// NewGZBMonitor 创建监控器。declaredCompressedLength 取 Content-Length（压缩态长度）。
func NewGZBMonitor(policy GZBPolicy, declaredCompressedLength int64) *GZBMonitor {
	return &GZBMonitor{policy: policy, declaredLen: declaredCompressedLength}
}

// GZBCheckEncodingLayers 校验 Content-Encoding 层数（逗号分隔）。
func GZBCheckEncodingLayers(contentEncoding string, policy GZBPolicy) (safe bool, findings []GZBFinding) {
	ce := trimSpaceGZB(contentEncoding)
	if ce == "" {
		return true, nil
	}
	layers := 0
	for _, tok := range splitCommaGZB(ce) {
		if trimSpaceGZB(tok) != "" {
			layers++
		}
	}
	if layers > policy.MaxEncodingLayers {
		findings = append(findings, GZBFinding{Reason: GZBReasonNestedEncoding,
			Detail: itoaGZB(layers)})
	}
	return len(findings) == 0, findings
}
