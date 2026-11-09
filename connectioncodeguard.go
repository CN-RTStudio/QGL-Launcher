package main

import (
	"strconv"
	"strings"
)

const (
	// connCodeParts 连接码必须恰好由 首段 + 3 个 IP 段 + 端口 = 5 部分组成。
	connCodeParts = 5
	// maxXPrefixDigits 限制 X 前缀后的十进制位数：IPv4 段最大 255（3 位），
	// 再长一定越界，直接在解析阶段拒绝，避免喂入超大整数。
	maxXPrefixDigits = 3
)
const (
	connRejectNone    = ""
	connRejectShape   = "bad-code-shape"    // 段数不对
	connRejectPrefix  = "bad-prefix"        // 首段前缀非法 / 越界
	connRejectSegment = "bad-ip-segment"    // 后三段非十六进制 / 越界
	connRejectPort    = "bad-code-port"     // 端口非十六进制 / 越界
	connRejectAddress = "bad-final-address" // 还原地址形态校验失败
)

func decodePrefix(prefix string) (int, bool) {
	switch prefix {
	case "A":
		return 10, true
	case "B":
		return 172, true
	case "C":
		return 192, true
	case "D":
		return 1, true
	}
	if !strings.HasPrefix(prefix, "X") || len(prefix) < 2 {
		return 0, false
	}
	digits := prefix[1:]
	// 显式长度限制 + 纯数字校验：拒绝 X-1、X+1、X、X 空串、超长串。
	if len(digits) > maxXPrefixDigits {
		return 0, false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n < 0 || n > 255 {
		return 0, false
	}
	return n, true
}
