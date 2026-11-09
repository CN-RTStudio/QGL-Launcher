package main

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
