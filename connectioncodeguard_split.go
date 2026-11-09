package main

//
//
//

import (
	"strconv"
	"strings"
)

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
