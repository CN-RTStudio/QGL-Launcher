package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

func parseAccessRecords(raw []byte) ([]accessRecord, error) {
	var records []accessRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func auditAccessRecords(file string, records []accessRecord) []AccessFinding {
	findings := []AccessFinding{}
	seenUUID := map[string]int{}
	for index, record := range records {
		entry := strings.TrimSpace(record.UUID)
		if entry == "" {
			entry = fmt.Sprintf("#%d", index+1)
		}
		if file == "banned-ips.json" {
			findings = append(findings, auditBannedIP(file, entry, record)...)
			continue
		}
		if reason, detail := validateAccessUUID(record.UUID); reason != "" {
			findings = append(findings, AccessFinding{File: file, Entry: entry, Reason: reason, Detail: detail, Blocking: true})
		}
		if reason, detail := validateAccessName(record.Name); reason != "" {
			findings = append(findings, AccessFinding{File: file, Entry: entry, Reason: reason, Detail: detail, Blocking: true})
		}
		normalized := normalizeAccessUUID(record.UUID)
		if normalized != "" {
			if first, ok := seenUUID[normalized]; ok {
				findings = append(findings, AccessFinding{
					File: file, Entry: entry, Reason: accessReasonDuplicate,
					Detail: fmt.Sprintf("与第 %d 条记录 UUID 重复", first+1), Blocking: true,
				})
			} else {
				seenUUID[normalized] = index
			}
		}
		if file == "ops.json" && record.Level != 0 {
			if record.Level < accessMinOpsLevel || record.Level > accessMaxOpsLevel {
				findings = append(findings, AccessFinding{
					File: file, Entry: entry, Reason: accessReasonBadEntry,
					Detail:   fmt.Sprintf("op 等级 %d 超出 %d-%d", record.Level, accessMinOpsLevel, accessMaxOpsLevel),
					Blocking: true,
				})
			} else if record.Level == accessMaxOpsLevel {
				findings = append(findings, AccessFinding{
					File: file, Entry: entry, Reason: accessReasonBadEntry,
					Detail: "op 等级 4 拥有完全控制权", Blocking: false,
				})
			}
		}
	}
	return findings
}

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
