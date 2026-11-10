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

func DecodeConnectionCode(code string) (string, string) {
	parts := strings.Split(code, "-")
	if len(parts) != connCodeParts {
		return "", connRejectShape
	}

	firstSeg, ok := decodePrefix(parts[0])
	if !ok {
		return "", connRejectPrefix
	}

	segments := make([]int, 0, 3)
	for i := 1; i <= 3; i++ {
		seg, ok := parseHexSegment(parts[i])
		if !ok {
			return "", connRejectSegment
		}
		segments = append(segments, seg)
	}

	port, ok := parseHexSegment(parts[4])
	if !ok {
		return "", connRejectPort
	}
	// 端口最终沿用启动器统一的端口白名单（与创建服务器一致），而不是只判 0-255。
	if !isValidPort(port) {
		return "", connRejectPort
	}

	address := strconv.Itoa(firstSeg) + "." +
		strconv.Itoa(segments[0]) + "." +
		strconv.Itoa(segments[1]) + "." +
		strconv.Itoa(segments[2]) + ":" +
		strconv.Itoa(port)

	// 末端用通用地址内核复核形态，防止任何边角情况输出脏地址。
	if norm, why := ValidateHostPort(address); why == addrRejectNone {
		return norm, connRejectNone
	}
	return "", connRejectAddress
}

func EncodeConnectionCode(ipv4 string, port int) (string, string) {
	norm, ok := NormalizeIPv4(strings.TrimSpace(ipv4))
	if !ok {
		return "", connRejectAddress
	}
	if !isValidPort(port) {
		return "", connRejectPort
	}
	segs := strings.Split(norm, ".")
	segNums := [4]int{}
	for i := 0; i < 4; i++ {
		n, _ := strconv.Atoi(segs[i])
		segNums[i] = n
	}
	prefix, ok := encodePrefix(segNums[0])
	if !ok {
		return "", connRejectPrefix
	}
	return strings.Join([]string{
		prefix,
		strconv.FormatInt(int64(segNums[1]), 16),
		strconv.FormatInt(int64(segNums[2]), 16),
		strconv.FormatInt(int64(segNums[3]), 16),
		strconv.FormatInt(int64(port), 16),
	}, "-"), connRejectNone
}

// describeConnReject 把连接码拒绝原因码转成中文说明，供上层返回给前端。
func describeConnReject(why string) string {
	return rejectReasonText(why, "连接码解析失败", describeConnRejectTexts)
}
