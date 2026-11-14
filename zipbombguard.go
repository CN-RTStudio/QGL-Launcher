package main

// zipbombguard.go —— 压缩包解压前的资源放大（zip bomb）守卫。
//
// 背景：
//   modpack、资源包、存档常以 zip 分发。恶意包用高压缩比小条目放大成 TB 级数据，或靠海量小条目
//   耗尽 inode/句柄，或用重叠的 local header 让不同解析器看到不同大小。解压侧（jarentryguard 负责
//   路径穿越/链接）之外，还需要在"聚合资源预算"层面设限：
//     - 单条目解压大小上限；
//     - 压缩后→解压后字节放大比上限；
//     - 全包解压总量与条目数上限；
//     - 0 字节/极小压缩载荷却声明巨大解压大小（声明不一致）；
//     - 累计写出量超过磁盘可用预算。
//   本模块维护有界聚合状态，纯数值判定，不使用正则。

const (
	ZBReasonEntryTooLarge    = "zip-entry-uncompressed-size-exceeds-limit"
	ZBReasonRatioTooHigh     = "zip-entry-compression-ratio-exceeds-limit"
	ZBReasonTotalTooLarge    = "zip-archive-total-uncompressed-exceeds-limit"
	ZBReasonTooManyEntries   = "zip-archive-entry-count-exceeds-limit"
	ZBReasonDeclaredMismatch = "zip-entry-declared-size-inconsistent-with-stream"
	ZBReasonDiskBudget       = "zip-expanded-total-exceeds-available-disk-budget"
)

// 缺省预算。
const (
	ZBMaxEntryBytes = 2 << 30  // 单条目 2 GiB
	ZBMaxTotalBytes = 16 << 30 // 全包 16 GiB
	ZBMaxEntries    = 200000
	ZBMaxRatio      = 256 // 单条目压缩比
)

// ZBEntry 是一条目已观察到的度量。
type ZBEntry struct {
	CompressedSize   int64
	UncompressedSize int64
}

// ZBFinding 记录一处问题。
type ZBFinding struct {
	Reason string
	Detail string
}

// ZBAuditor 累积聚合预算。
type ZBAuditor struct {
	Limits ZBLimits
	seen   int
	total  int64
}

// ZBLimits 允许调用方覆盖预算；零值字段用缺省值。
type ZBLimits struct {
	MaxEntryBytes int64
	MaxTotalBytes int64
	MaxEntries    int
	MaxRatio      int
	DiskFreeBytes int64 // 0 表示不检查磁盘预算
}

func (l *ZBLimits) fill() {
	if l.MaxEntryBytes <= 0 {
		l.MaxEntryBytes = ZBMaxEntryBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = ZBMaxTotalBytes
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = ZBMaxEntries
	}
	if l.MaxRatio <= 0 {
		l.MaxRatio = ZBMaxRatio
	}
}

// ZBNewAuditor 创建审计器。
func ZBNewAuditor(limits ZBLimits) *ZBAuditor {
	limits.fill()
	return &ZBAuditor{Limits: limits}
}

// ZBAuditEntry 在解压某条目前校验并记账。streamBytes<0 表示尚无流式实际值可比对。
