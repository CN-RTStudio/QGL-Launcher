package main

// connectioncodeguard.go —— 局域网“联机连接码”的严格编解码内核。
//
// 连接码形如  P-s2-s3-s4-port （段之间用 '-' 分隔）：
//   - P 是首段 IPv4 的压缩前缀：A=10、B=172、C=192、D=1；其余首段写成 X<十进制>。
//   - s2/s3/s4 是 IPv4 后三段的【十六进制】；
//   - port 是端口的【十六进制】。
//
// 威胁模型：
//   旧 ParseConnectionCode 在解析 X<数字> 前缀时，strconv.Atoi 的结果直接作为首段，
//   没有做 0-255 范围校验，也没有限制前缀长度——X999、X-1、X999999999999 都能被接受，
//   拼出一个根本不是合法 IPv4 的地址（999.x.x.x、负数段、溢出后语义不定）。畸形连接码
//   来自外部输入（用户手输 / 他人分享），最终会被当成服务器地址使用，属于未校验输入。
//   生成侧与解析侧此前各写一套逻辑，也容易出现“编出来却解不回去”的不一致。
//
// 本内核把编解码收敛成纯函数并保证两侧对称：
//   - 首段 0-255（A/B/C/D 白名单或受长度限制的 X 十进制，拒绝负号 / 加号 / 空 / 溢出）；
//   - 后三段严格十六进制且 0-255；端口严格十六进制且通过 isValidPort；
//   - 恰好五段，拒绝空段、多余分隔符、大小写以外的脏字符；
//   - 还原出的地址再过 netaddrguard 形态校验，确保输出一定是干净的 IPv4:端口。
// 不做任何 IO，便于穷举单测。

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

// EncodeConnectionCode 是 DecodeConnectionCode 的逆：给定点分十进制 IPv4 与端口，
// 生成规范连接码。供生成侧统一调用，保证“编得出就解得回”。
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
	switch why {
	case connRejectShape:
		return "连接码格式错误"
	case connRejectPrefix:
		return "连接码首段前缀无法解析或越界"
	case connRejectSegment:
		return "连接码 IP 段解析失败"
	case connRejectPort:
		return "解析出的端口号无效"
	case connRejectAddress:
		return "连接码还原的地址不合法"
	default:
		return "连接码解析失败"
	}
}
