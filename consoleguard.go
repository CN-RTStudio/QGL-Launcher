package main

// consoleguard.go —— 服务器控制台 stdin 写入的统一安全内核。
//
// 威胁模型：
//
//	SendServerCommand 是前端（Wails 渲染进程）唯一能直达 Minecraft 服务端进程
//	stdin 的通道，每调用一次就向子进程写入一行 "<cmd>\n"。历史实现只挡了 "\n"/"\r"，
//	存在几类真实缺口：
//	  1. 长度无上限：前端可塞入数 MB 甚至更大的一行，写穿 stdin 管道后进入服务端
//	     日志 / RCON 转发 / 控制台界面，造成内存与磁盘放大；
//	  2. 仅挡 CR/LF，NUL（0x00）、其它 C0 控制字符（BEL/ESC/退格等）、DEL（0x7F）、
//	     Unicode 行分隔符 U+2028/U+2029、BOM U+FEFF 原样放行：NUL 会截断 C 层字符串，
//	     ESC 序列可污染抓取日志的终端，U+2028/U+2029 在 JS 侧按行切日志时会被当成换行；
//	  3. 非法 UTF-8 字节直接写进子进程，下游按 UTF-8 解码的日志/界面会出现替换符与错位；
//	  4. 没有速率闸：被攻破或出现 bug 的渲染层可在循环里高速灌命令，打爆服务端日志磁盘
//	     与存档（大量 say / fill / clone 类命令会落盘）。
//
// 本内核一律“拒绝而非静默改写”：命中规则返回原因码，由 server.go 放弃写入并记安全
// 事件，避免把用户输入悄悄改短后发到一个他们并不想要的目标。所有函数均为纯逻辑 /
// 自带互斥的门闸，可直接做单元测试。

import (
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	// maxConsoleCommandBytes 单行控制台命令（不含结尾换行）的字节上限。
	// 真实环境里最长的合法命令是带 NBT / 选择器参数的 give/summon，通常 1~2KB；
	// 给到 16KiB 已远超任何手工命令，足以挡住 MB 级灌入，又不会误伤正常使用。
	maxConsoleCommandBytes = 16 << 10
)

// 拒绝原因码：空串表示通过。
const (
	consoleRejectNone     = ""
	consoleRejectEmpty    = "empty"      // 去首尾空白后为空行
	consoleRejectNewline  = "newline"    // 夹带 CR/LF，企图一行拆多条命令注入
	consoleRejectControl  = "control"    // 含 NUL/其它 C0/DEL/U+2028/U+2029/BOM 等
	consoleRejectEncoding = "encoding"   // 非法 UTF-8
	consoleRejectLength   = "too-long"   // 超过单行字节上限
	consoleRejectRate     = "rate-limit" // 触发高速灌入限流
)

// 速率闸阈值。控制台命令的正常节奏很低（人工逐条输入），这里取非常宽松的上限：
// 短窗 5 秒最多 40 条、长窗 60 秒最多 240 条（约 4 条/秒持续），任一窗口超限即进入
// 15 秒冷却，冷却期内全部拒绝。任何真人操作都到不了这个量级，只有循环刷命令才会命中。
const (
	consoleBurstWindow = 5 * time.Second
	consoleBurstMax    = 40
	consoleLongWindow  = 60 * time.Second
	consoleLongMax     = 240
	consoleCooldown    = 15 * time.Second
)

// SanitizeConsoleCommand 校验一条准备写入服务端 stdin 的命令 / 聊天行。
//
// 返回可安全写入的行（已去首尾空白、不含结尾换行）与拒绝原因码；原因码非空表示
// 必须放弃本次写入。
func SanitizeConsoleCommand(raw string) (string, string) {
	// 官方服务端控制台读取时本身会 trim，首尾空白不携带语义，先统一去掉，
	// 也避免用一堆空格把行撑到长度阈值之上。
	cmd := strings.TrimSpace(raw)
	if cmd == "" {
		return "", consoleRejectEmpty
	}
	// CR/LF 必须在长度与字节遍历之前先挡，明确区分“命令注入”这一原因。
	if strings.ContainsAny(cmd, "\n\r") {
		return "", consoleRejectNewline
	}
	if len(cmd) > maxConsoleCommandBytes {
		return "", consoleRejectLength
	}
	if !utf8.ValidString(cmd) {
		return "", consoleRejectEncoding
	}
	for _, r := range cmd {
		if r < 0x20 || r == 0x7f {
			// 0x00-0x1F 全部 C0 控制字符（含 NUL/BEL/ESC/Tab/VT 等）与 DEL。
			return "", consoleRejectControl
		}
		switch r {
		case 0x2028, 0x2029, 0xfeff:
			// U+2028/U+2029 行 / 段分隔符，U+FEFF BOM：日志按行处理时会被当成换行。
			return "", consoleRejectControl
		}
	}
	return cmd, consoleRejectNone
}

// consoleCommandGate 是控制台写入的滑动双窗口限流器，并发安全。
type consoleCommandGate struct {
	mu            sync.Mutex
	burstStart    time.Time
	burstCount    int
	longStart     time.Time
	longCount     int
	cooldownUntil time.Time
}

// allow 判断当前时刻是否放行一条命令；一旦短窗或长窗超阈，立即进入冷却期并拒绝。
// 冷却期结束后所有计数重新开始。
func (g *consoleCommandGate) allow(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if now.Before(g.cooldownUntil) {
		return false
	}
	// 短窗口滑动：距首条已超过窗口则开窗重新计数。
	if g.burstStart.IsZero() || now.Sub(g.burstStart) > consoleBurstWindow {
		g.burstStart = now
		g.burstCount = 0
	}
	// 长窗口滑动。
	if g.longStart.IsZero() || now.Sub(g.longStart) > consoleLongWindow {
		g.longStart = now
		g.longCount = 0
	}

	g.burstCount++
	g.longCount++
	if g.burstCount > consoleBurstMax || g.longCount > consoleLongMax {
		g.cooldownUntil = now.Add(consoleCooldown)
		// 进入冷却即清空窗口，冷却结束后从干净状态重新计数。
		g.burstStart = time.Time{}
		g.burstCount = 0
		g.longStart = time.Time{}
		g.longCount = 0
		return false
	}
	return true
}

// reset 清空限流状态，在新的服务端进程启动时调用，避免上一轮冷却误伤本次会话。
func (g *consoleCommandGate) reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.burstStart = time.Time{}
	g.burstCount = 0
	g.longStart = time.Time{}
	g.longCount = 0
	g.cooldownUntil = time.Time{}
}

// serverConsoleGate 是 SendServerCommand 共用的包级限流闸。
var serverConsoleGate consoleCommandGate
