package main

// http2rapidguard.go —— HTTP/2 Rapid Reset（CVE-2023-44487 类）客户端侧流取消洪水守卫。
//
// 背景：
//   启动器要并发拉取 manifest、库、资产、Modrinth 列表。HTTP/2 多路复用下，恶意（或被劫）服务端
//   与客户端之间存在流的创建/取消（RST_STREAM / CANCEL）。Rapid Reset 攻击表现为"发大量请求后立刻
//   取消"，让对端为其分配资源却拿不到完整处理，形成放大与 DoS。即便我们是客户端，也要防止：
//     - 自身（或被上层逻辑诱导）短时间创建又取消大量流，被服务器封禁/耗尽连接；
//     - 对端诱导我们反复重连（GOAWAY 后立即风暴式重建）；
//     - 并发活跃流超过对端 SETTINGS_MAX_CONCURRENT_STREAMS；
//     - 取消速率 / 取消与请求之比异常高。
//   本模块是纯计数状态机，喂入 open/reset/goaway/close 等事件后给结论；不实现 HTTP/2 协议栈，
//   不使用正则。

const (
	H2ReasonResetBurst       = "http2-rapid-reset-burst"
	H2ReasonResetRatio       = "http2-high-reset-to-request-ratio"
	H2ReasonConcurrentStream = "http2-exceeds-max-concurrent-streams"
	H2ReasonGOAWAYReconnect  = "http2-goaway-reconnect-storm"
	H2ReasonUnknownStream    = "http2-reset-for-unknown-stream"
	H2ReasonWindowExhausted  = "http2-stream-window-exhausted"
)

// H2Policy 设定流控闸门（数值仅作默认，调用方可按对端 SETTINGS 覆盖）。
type H2Policy struct {
	MaxConcurrentStreams int // 对端通告的 MAX_CONCURRENT_STREAMS
	MaxResetPerWindow    int // 一个时间窗内允许的 RST_STREAM 数
	ResetRatioPercent    int // reset/opened 百分比上限
	MaxGOAWAYReconnects  int // 时间窗内 GOAWAY 后允许的重建次数
	WindowTicks          int // 窗口长度（以"tick"为抽象单位，由调用方映射到时间）
}

// DefaultH2Policy 默认：并发 100、窗口 64、窗口内 reset 100、比例 80%、重建 3。
func DefaultH2Policy() H2Policy {
	return H2Policy{
		MaxConcurrentStreams: 100,
		MaxResetPerWindow:    100,
		ResetRatioPercent:    80,
		MaxGOAWAYReconnects:  3,
		WindowTicks:          100,
	}
}

// H2Finding 记录一处 HTTP/2 滥用。
type H2Finding struct {
	Reason string
	Detail string
}

// H2Monitor 是单条 HTTP/2 连接（或一个连接池）的事件监控。
type H2Monitor struct {
	policy H2Policy

	active map[int]bool
	opened int
	reset  int

	// 环形窗口记录每个 tick 的 reset 数
	resetWindow []int
	tick        int

	goawaySeen       bool
	reconnectsWindow int
	blocked          bool
	blockedReason    string
}

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
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
