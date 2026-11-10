package main

type JarFinding struct {
	Rule     string             `json:"rule"`
	Severity JarFindingSeverity `json:"severity"`
	Entry    string             `json:"entry"`
	Detail   string             `json:"detail"`
}

// JarScanReport 是一次扫描的完整结果。
type JarScanReport struct {
	Entries        int          `json:"entries"`
	ClassFiles     int          `json:"classFiles"`
	ScannedClasses int          `json:"scannedClasses"`
	Findings       []JarFinding `json:"findings"`
	HasModMarker   bool         `json:"hasModMarker"`
	NestedJars     int          `json:"nestedJars"`
	NativeLibs     int          `json:"nativeLibs"`

	// ruleSeen 对同一规则只报一次，避免一个 jar 里上百个 class 刷屏。
	ruleSeen map[string]bool

	// 以下为跨嵌套层级共享的扫描状态，不参与 JSON 序列化。
	limitedEntries   bool
	nestedLimitDepth bool
	nestedLimitCount bool
}

// Blocked 报告是否存在必须阻断安装的 critical 发现。
func (r *JarScanReport) Blocked() bool {
	if r == nil {
		return false
	}
	return anyBlocking(r.Findings, func(f JarFinding) bool { return f.Severity == JarSeverityCritical })
}
