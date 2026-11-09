package main

import (
	"strconv"
)

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

// OnReset 记录流被取消（RST_STREAM / CANCEL）。
func (m *H2Monitor) OnReset(streamID int) (allowed bool, findings []H2Finding) {
	if !m.active[streamID] {
		// 取消一个我们没有的活跃流：可疑的伪造/重放
		return false, []H2Finding{{Reason: H2ReasonUnknownStream,
			Detail: itoaH2(streamID)}}
	}
	delete(m.active, streamID)
	m.reset++

	idx := m.tick % len(m.resetWindow)
	m.resetWindow[idx]++

	if m.windowReset() > m.policy.MaxResetPerWindow {
		m.block(H2ReasonResetBurst, itoaH2(m.windowReset()))
		return false, []H2Finding{{Reason: H2ReasonResetBurst}}
	}

	if m.opened > 0 {
		ratio := m.reset * 100 / m.opened
		if ratio > m.policy.ResetRatioPercent && m.opened >= 10 {
			m.block(H2ReasonResetRatio, itoaH2(ratio))
			return false, []H2Finding{{Reason: H2ReasonResetRatio,
				Detail: itoaH2(ratio)}}
		}
	}
	return true, nil
}

// OnGOAWAY 记录收到 GOAWAY。
func (m *H2Monitor) OnGOAWAY() {
	m.goawaySeen = true
}

// OnReconnect 记录 GOAWAY 后的一次重建尝试。
func (m *H2Monitor) OnReconnect() (allowed bool, findings []H2Finding) {
	if !m.goawaySeen {
		return true, nil
	}
	m.reconnectsWindow++
	if m.reconnectsWindow > m.policy.MaxGOAWAYReconnects {
		m.block(H2ReasonGOAWAYReconnect, itoaH2(m.reconnectsWindow))
		return false, []H2Finding{{Reason: H2ReasonGOAWAYReconnect,
			Detail: itoaH2(m.reconnectsWindow)}}
	}
	return true, nil
}

func (m *H2Monitor) windowReset() int {
	sum := 0
	for _, n := range m.resetWindow {
		sum += n
	}
	return sum
}

func (m *H2Monitor) block(reason, _ string) {
	m.blocked = true
	m.blockedReason = reason
}

// Blocked 报告监控是否已判定需要熔断。
func (m *H2Monitor) Blocked() bool { return m.blocked }

// BlockedReason 返回熔断原因。
func (m *H2Monitor) BlockedReason() string { return m.blockedReason }

// ActiveCount 返回当前活跃流数。
func (m *H2Monitor) ActiveCount() int { return len(m.active) }

func itoaH2(i int) string {
	return strconv.Itoa(i)
}
