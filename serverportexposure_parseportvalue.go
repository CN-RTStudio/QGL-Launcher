package main

import (
	"strconv"
	"strings"
)

func parsePortValue(key, raw string) (int, *PortFinding) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, &PortFinding{Key: key, Value: raw, Reason: portReasonBadNumber, Detail: "端口为空", Blocking: true}
	}
	if strings.HasPrefix(trimmed, "-") || strings.ContainsAny(trimmed, " \t") {
		return 0, &PortFinding{Key: key, Value: raw, Reason: portReasonBadNumber, Detail: "端口含非法字符", Blocking: true}
	}
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] < '0' || trimmed[i] > '9' {
			return 0, &PortFinding{Key: key, Value: raw, Reason: portReasonBadNumber, Detail: "端口含非数字字符", Blocking: true}
		}
	}
	if len(trimmed) > 1 && trimmed[0] == '0' {
		return 0, &PortFinding{Key: key, Value: raw, Reason: portReasonBadNumber, Detail: "端口含前导零歧义", Blocking: true}
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, &PortFinding{Key: key, Value: raw, Reason: portReasonBadNumber, Detail: "端口不是整数", Blocking: true}
	}
	if value < 1 || value > 65535 {
		return value, &PortFinding{Key: key, Value: raw, Reason: portReasonOutOfRange, Detail: "端口超出 1-65535", Blocking: true}
	}
	return value, nil
}
