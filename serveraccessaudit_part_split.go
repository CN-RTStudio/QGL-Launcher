package main

import (
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

func auditBannedIP(file, entry string, record accessRecord) []AccessFinding {
	if reason, detail := validateAccessIP(record.IP); reason != "" {
		return []AccessFinding{{File: file, Entry: entry, Reason: reason, Detail: detail, Blocking: true}}
	}
	ip := net.ParseIP(strings.TrimSpace(record.IP))
	if ip == nil {
		return nil
	}
	findings := []AccessFinding{}
	if ip.IsUnspecified() {
		findings = append(findings, AccessFinding{
			File: file, Entry: entry, Reason: accessReasonBadEntry,
			Detail: "封禁 0.0.0.0/:: 会拒绝全部地址", Blocking: true,
		})
	}
	if ip.IsLoopback() {
		findings = append(findings, AccessFinding{
			File: file, Entry: entry, Reason: accessReasonBadEntry,
			Detail: "封禁回环地址没有实际意义", Blocking: false,
		})
	}
	return findings
}

func validateAccessIP(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return accessReasonBadEntry, "缺少 ip 字段"
	}
	if len(value) > 64 {
		return accessReasonBadEntry, "ip 字段长度超限"
	}
	if net.ParseIP(value) == nil {
		return accessReasonBadEntry, "ip 字段不是合法地址"
	}
	return "", ""
}

func validateAccessUUID(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return accessReasonBadEntry, "缺少 uuid 字段"
	}
	normalized := normalizeAccessUUID(value)
	if len(normalized) != 32 || !IsLowerHex(normalized, 32) {
		return accessReasonBadEntry, "uuid 不是 32 位十六进制"
	}
	return "", ""
}

func normalizeAccessUUID(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.ReplaceAll(value, "-", "")
	return value
}

func validateAccessName(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return accessReasonBadEntry, "缺少 name 字段"
	}
	if utf8.RuneCountInString(value) > accessMaxNameRunes {
		return accessReasonBadEntry, fmt.Sprintf("name 超过 %d 字符", accessMaxNameRunes)
	}
	if containsControlByte(value) {
		return accessReasonBadEntry, "name 含控制字符"
	}
	if strings.ContainsAny(value, "/\\:\"'") {
		return accessReasonBadEntry, "name 含路径或引号字符"
	}
	return "", ""
}
