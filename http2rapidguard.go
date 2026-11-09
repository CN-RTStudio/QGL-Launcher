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
