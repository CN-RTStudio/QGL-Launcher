package main

// diskwriteguard.go —— 下载落盘过程中的“实时已写字节”磁盘守卫（纯逻辑）。
//
// diskspaceguard 的预检发生在下载开始前，依赖声明大小；但 HTTP 响应可能是 chunked
// 传输（ContentLength=-1），或服务端给的 fileSize 不准 / 干脆未知（0）。这种情况下
// 预检拦不住“写着写着才发现是个超大文件”。本守卫在写入循环里逐块累计“实际已写字节”，
// 每写一块都与下载开始时探测到的卷剩余空间比较：一旦已写量会把可用空间压到安全水位
// 之下，立即判定必须中止，由调用方关闭并删除 .part 临时文件。
//
// 它只做纯算术（不碰文件系统 / 不做 syscall），平台探测由 availableDiskBytes 完成、
// 在构造守卫时传入一次即可，因此在任意平台都能确定性单测。
//
// 与既有上限的关系：单文件还有 MaxBytesReader 的 effectiveCap（按 Modrinth 声明大小）
// 兜底；本守卫补的是“声明缺失 / chunked”这一支，并以物理磁盘真实余量为准绳。裁决
// 直接复用 assessDiskFit，保证“开始前预检”和“写入中复检”口径完全一致。

// diskWriteGuard 跟踪一次下载（或同一目录的一串写入）已实际落盘的字节数。
type diskWriteGuard struct {
	initialAvail int64 // 下载开始时探测到的可用字节；<0 表示未知（守卫停用，绝不误杀）
	headroom     int64 // 必须保留的安全水位
	written      int64 // 截至目前累计已写字节
	verdict      diskFitVerdict
	shortfall    int64
	disabled     bool // initialAvail<0 时为 true，recordChunk 永远放行
}

// newDiskWriteGuard 用“开始时可用字节 + 安全水位”构造守卫。
// avail<0（探测失败 / 未知）时守卫进入停用模式：保留计数但从不拦截，
// 符合“没有证据不能误杀正常下载”。headroom<=0 时回退到全局默认水位。
func newDiskWriteGuard(avail, headroom int64) *diskWriteGuard {
	if headroom <= 0 {
		headroom = diskReserveHeadroomBytes
	}
	g := &diskWriteGuard{
		initialAvail: avail,
		headroom:     headroom,
		verdict:      diskFitOK,
	}
	if avail < 0 {
		g.disabled = true
		g.verdict = diskFitUnknown
	}
	return g
}

// Written 返回累计已写字节。
func (g *diskWriteGuard) Written() int64 { return g.written }

// Disabled 报告守卫是否因初始余量未知而停用。
func (g *diskWriteGuard) Disabled() bool { return g.disabled }

// Verdict 返回当前裁决（ok / short / bad-input / unknown）。
func (g *diskWriteGuard) Verdict() diskFitVerdict { return g.verdict }

// Shortfall 返回击穿水位时的缺口字节（仅 short 有意义）。
func (g *diskWriteGuard) Shortfall() int64 { return g.shortfall }

// Remaining 返回“在击穿水位前还允许写多少字节”。
// 未知（停用）返回 -1；预算已打满 / 击穿返回 0；否则返回非负可写余量。
func (g *diskWriteGuard) Remaining() int64 {
	if g.disabled {
		return diskAvailUnknown
	}
	budget := g.initialAvail - g.headroom
	if budget <= 0 {
		return 0
	}
	left := budget - g.written
	if left < 0 {
		return 0
	}
	return left
}

// recordChunk 登记“刚成功写入 n 字节”，返回是否仍允许继续写。
//
//	n<0            -> bad-input，allow=false（调用方读到非法长度应中止）
//	累计溢出 int64  -> bad-input，allow=false
//	守卫停用        -> 只累加计数，始终 allow=true（unknown 不拦）
//	累计写穿水位    -> short，allow=false，Shortfall 给出缺口
func (g *diskWriteGuard) recordChunk(n int64) (bool, DiskFitAssessment) {
	assess := DiskFitAssessment{
		Available:  g.initialAvail,
		AfterWrite: diskAvailUnknown,
	}
	if n < 0 {
		g.verdict = diskFitBadInput
		assess.Verdict = diskFitBadInput
		assess.Requested = g.written
		return false, assess
	}
	candidate, ok := addChecked(g.written, n)
	if !ok {
		g.verdict = diskFitBadInput
		assess.Verdict = diskFitBadInput
		assess.Requested = g.written
		return false, assess
	}
	assess.Requested = candidate

	if g.disabled {
		// 已写计数仍保留（供上层观察），但未知余量下绝不拦截。
		g.written = candidate
		g.verdict = diskFitUnknown
		assess.Verdict = diskFitUnknown
		return true, assess
	}

	// 已被判 short 后持续拒绝，避免“拒一次又放行”的抖动。
	if g.verdict == diskFitShort {
		assess.Verdict = diskFitShort
		assess.AfterWrite = g.initialAvail - g.written
		assess.Shortfall = g.shortfall
		return false, assess
	}

	// 直接复用预检裁决：候选已写量当作“本次申请写入量”，没有额外在途预留。
	// 只有裁决 ok 才推进 written——被拒的一块在调用方根本不会落盘，不能把它
	// 记成“已写”，否则计数会虚大于磁盘真实占用。
	fit := assessDiskFit(g.initialAvail, candidate, 0)
	if fit.Verdict == diskFitOK {
		g.written = candidate
		g.verdict = diskFitOK
		assess.Verdict = diskFitOK
		assess.AfterWrite = fit.AfterWrite
		return true, assess
	}
	// short / bad-input 都需中止，written 保持为最后一次成功写入的值。
	g.verdict = fit.Verdict
	g.shortfall = fit.Shortfall
	assess.Verdict = fit.Verdict
	assess.AfterWrite = fit.AfterWrite
	assess.Shortfall = fit.Shortfall
	return false, assess
}

// describeDiskWriteAbort 给出中止下载时的中文错误说明（unknown / ok 返回空串）。
func describeDiskWriteAbort(g *diskWriteGuard) string {
	if g == nil {
		return ""
	}
	switch g.verdict {
	case diskFitShort:
		return "磁盘空间在下载过程中不足，已中止并删除残片（还差 " +
			FormatBytes(g.shortfall) + "）"
	case diskFitBadInput:
		return "下载写入长度非法，已中止"
	default:
		return ""
	}
}
