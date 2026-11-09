package main

// NewH2Monitor 创建监控器。
func NewH2Monitor(policy H2Policy) *H2Monitor {
	w := policy.WindowTicks
	if w <= 0 {
		w = 1
	}
	return &H2Monitor{
		policy:      policy,
		active:      map[int]bool{},
		resetWindow: make([]int, w),
	}
}

// SetMaxConcurrent 用对端 SETTINGS 帧更新并发上限（只能收紧/放宽到真实通告）。
func (m *H2Monitor) SetMaxConcurrent(n int) {
	if n > 0 {
		m.policy.MaxConcurrentStreams = n
	}
}

// AdvanceTick 推进一个抽象时间单位，滚动 reset 窗口。
func (m *H2Monitor) AdvanceTick() {
	m.tick++
	idx := m.tick % len(m.resetWindow)
	m.resetWindow[idx] = 0
	if m.goawaySeen {
		// 窗口滑过一个完整周期后允许再次重建
		if m.tick%len(m.resetWindow) == 0 {
			m.reconnectsWindow = 0
		}
	}
}

// OnOpen 记录一个流被打开。streamID 为 HTTP/2 流 ID。
func (m *H2Monitor) OnOpen(streamID int) (allowed bool, findings []H2Finding) {
	if m.blocked {
		return false, []H2Finding{{Reason: m.blockedReason}}
	}
	if m.active[streamID] {
		// 重复打开同 ID 属于协议异常
		return false, []H2Finding{{Reason: H2ReasonWindowExhausted,
			Detail: "duplicate-stream-" + itoaH2(streamID)}}
	}
	if len(m.active) >= m.policy.MaxConcurrentStreams {
		m.block(H2ReasonConcurrentStream, itoaH2(len(m.active)))
		return false, []H2Finding{{Reason: H2ReasonConcurrentStream,
			Detail: itoaH2(len(m.active))}}
	}
	m.active[streamID] = true
	m.opened++
	return true, nil
}
