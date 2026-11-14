package main

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
