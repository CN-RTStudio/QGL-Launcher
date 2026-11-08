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
func (a *ZBAuditor) ZBAuditEntry(e ZBEntry, streamBytes int64) (safe bool, findings []ZBFinding) {
	a.Limits.fill()
	if a.seen+1 > a.Limits.MaxEntries {
		findings = append(findings, ZBFinding{Reason: ZBReasonTooManyEntries,
			Detail: zbItoa(int64(a.seen + 1))})
	}
	if e.UncompressedSize > a.Limits.MaxEntryBytes {
		findings = append(findings, ZBFinding{Reason: ZBReasonEntryTooLarge,
			Detail: zbItoa(e.UncompressedSize)})
	}
	if zbRatioExceeds(e.CompressedSize, e.UncompressedSize, a.Limits.MaxRatio) {
		findings = append(findings, ZBFinding{Reason: ZBReasonRatioTooHigh,
			Detail: zbItoa(e.UncompressedSize) + "/" + zbItoa(e.CompressedSize)})
	}
	if a.total+e.UncompressedSize > a.Limits.MaxTotalBytes {
		findings = append(findings, ZBFinding{Reason: ZBReasonTotalTooLarge,
			Detail: zbItoa(a.total + e.UncompressedSize)})
	}
	if a.Limits.DiskFreeBytes > 0 &&
		a.total+e.UncompressedSize > a.Limits.DiskFreeBytes {
		findings = append(findings, ZBFinding{Reason: ZBReasonDiskBudget})
	}
	if streamBytes >= 0 && streamBytes != e.UncompressedSize {
		findings = append(findings, ZBFinding{Reason: ZBReasonDeclaredMismatch,
			Detail: zbItoa(e.UncompressedSize) + "!=" + zbItoa(streamBytes)})
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
func (a *ZBAuditor) ZBTotal() int64 { return a.total }

func zbRatioExceeds(compressed, uncompressed int64, maxRatio int) bool {
	if compressed <= 0 {
		// 0 字节却有非 0 解压大小，视为无限放大（但允许真空文件）
		return uncompressed > 0
	}
	if uncompressed <= 0 {
		return false
	}
	// uncompressed/compressed > maxRatio  <=> uncompressed > compressed*maxRatio，避免浮点
	var cm int64 = int64(maxRatio)
	if compressed > (1<<63-1)/cm {
		return false // 乘积溢出时压缩量本身已极大，放大有限
	}
	return uncompressed > compressed*cm
}

func zbItoa(i int64) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// ZBHasReason 判定结果含某类问题。
func ZBHasReason(findings []ZBFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
