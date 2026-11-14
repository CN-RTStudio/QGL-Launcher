package main

import (
	"strconv"
	"strings"
)

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
