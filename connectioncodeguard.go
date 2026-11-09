package main

//
//
//

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

// 连接码解析拒绝原因码。
const (
	connRejectNone    = ""
	connRejectShape   = "bad-code-shape"    // 段数不对
	connRejectPrefix  = "bad-prefix"        // 首段前缀非法 / 越界
	connRejectSegment = "bad-ip-segment"    // 后三段非十六进制 / 越界
	connRejectPort    = "bad-code-port"     // 端口非十六进制 / 越界
	connRejectAddress = "bad-final-address" // 还原地址形态校验失败
)

// decodePrefix 解析首段前缀，返回 IPv4 第一段数值与是否通过。
// A/B/C/D 为固定白名单；X<n> 必须是 1-3 位纯十进制且 0-255。
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

// encodePrefix 是 decodePrefix 的逆：按首段决定使用白名单字母还是 X<n>。
func encodePrefix(firstSeg int) (string, bool) {
	if firstSeg < 0 || firstSeg > 255 {
		return "", false
	}
	switch firstSeg {
	case 10:
		return "A", true
	case 172:
		return "B", true
	case 192:
		return "C", true
	case 1:
		return "D", true
	default:
		return "X" + strconv.Itoa(firstSeg), true
	}
}

// parseHexSegment 解析单个十六进制 IP 段，要求非空、纯十六进制、取值 0-255。
func parseHexSegment(token string) (int, bool) {
	if token == "" {
		return 0, false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(token, 16, 0)
	if err != nil || n < 0 || n > 255 {
		return 0, false
	}
	return int(n), true
}

// DecodeConnectionCode 把连接码解析为规范的 "IPv4:端口"。
// 任一环节非法都返回非空拒绝原因码，绝不返回半残地址。
