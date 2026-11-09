package main

const (
	// jarScanMaxEntries 限制单个 jar 参与分析的条目数，防海量条目耗尽 CPU。
	jarScanMaxEntries = 50000
	// jarScanTextCap 限制单个文本条目（MANIFEST/services）最多读取的字节数。
	jarScanTextCap = 1 << 20 // 1 MiB
	// jarScanMaxScannedClasses 限制参与字节码行为分析的 .class 条数。
	jarScanMaxScannedClasses = 2000
	// jarScanPerClassCap 限制单个 class 的读取字节数。
	jarScanPerClassCap = 1 << 20 // 1 MiB
	// jarScanClassBytesCap 限制一次扫描中所有 class 累计读取的字节数，
	// 防止超大 class 或海量 class 拖垮安装流程。
	jarScanClassBytesCap = 16 << 20 // 16 MiB
	// jarScanMaxNestedDepth 是嵌套 jar（JarJar）递归扫描的最大深度：
	// 外层 jar 记为第 1 层，最多向内再扫到第 2 层。
	jarScanMaxNestedDepth = 2
	// jarScanMaxNestedJars 限制一次扫描中参与递归的嵌套 jar 数量，防“jar 套娃”炸弹。
	jarScanMaxNestedJars = 32
	// jarScanNestedBytesCap 限制所有嵌套 jar 累计读取字节数。
	jarScanNestedBytesCap = 64 << 20 // 64 MiB
	// jarScanPerNestedCap 限制单个嵌套 jar 的读取字节数。
	jarScanPerNestedCap = 8 << 20 // 8 MiB
)

// JarFindingSeverity 与审计事件级别对齐。
type JarFindingSeverity string

const (
	JarSeverityInfo     JarFindingSeverity = "info"
	JarSeverityWarn     JarFindingSeverity = "warn"
	JarSeverityCritical JarFindingSeverity = "critical"
)

// JarFinding 是一条命中规则的发现。
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
	for _, f := range r.Findings {
		if f.Severity == JarSeverityCritical {
			return true
		}
	}
	return false
}
