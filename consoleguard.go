package main

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
