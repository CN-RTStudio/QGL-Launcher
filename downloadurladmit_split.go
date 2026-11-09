package main

import (
	"strings"
)

func describeDownloadURLReject(reason string) string {
	switch reason {
	case dqURLRejectNone:
		return "通过"
	case dqURLRejectScheme:
		return "URL 协议不是 http/https"
	case dqURLRejectUserinfo:
		return "URL 含 user:pass@ 形式的内嵌凭据"
	case dqURLRejectControl:
		return "URL 含控制字符、空白或 DEL"
	case dqURLRejectBackslash:
		return "URL 含反斜杠"
	case dqURLRejectHost:
		return "URL 主机名为空或含前导/尾随点"
	case dqURLRejectIPLiteral:
		return "URL 直接使用 IP 字面量（含十进制/十六进制/短格式/IPv6）"
	case dqURLRejectPort:
		return "URL 端口与协议默认端口不一致"
	case dqURLRejectMalformed:
		return "URL 结构不合法或缺少主机"
	case dqURLRejectEncoding:
		return "URL 主机含百分号编码或非 ASCII 字符"
	case dqURLRejectLong:
		return "URL 长度超过 4096 字节上限"
	default:
		return "URL 未通过安全校验"
	}
}

func validDownloadHostLabels(host string) bool {
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return false
		}
	}
	if len(labels) < 2 {
		return false
	}
	last := labels[len(labels)-1]
	for i := 0; i < len(last); i++ {
		if last[i] >= '0' && last[i] <= '9' {
			return false
		}
	}
	return true
}
