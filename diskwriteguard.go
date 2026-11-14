package main

type diskWriteGuard struct {
	initialAvail int64 // 下载开始时探测到的可用字节；<0 表示未知（守卫停用，绝不误杀）
	headroom     int64 // 必须保留的安全水位
	written      int64 // 截至目前累计已写字节
	verdict      diskFitVerdict
	shortfall    int64
	disabled     bool // initialAvail<0 时为 true，recordChunk 永远放行
}

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

func (g *diskWriteGuard) Written() int64 { return g.written }

// Disabled 报告守卫是否因初始余量未知而停用。
