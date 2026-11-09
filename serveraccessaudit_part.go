package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func auditAccessFile(serverDir, name string) (AccessFileAudit, error) {
	out := AccessFileAudit{Name: name}
	path := filepath.Join(serverDir, name)
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	out.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		out.Symlink = true
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonSymlink, Detail: "权限文件是符号链接", Blocking: true,
		})
		return out, nil
	}
	if !info.Mode().IsRegular() {
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonNotRegular, Detail: "权限文件不是普通文件", Blocking: true,
		})
		return out, nil
	}
	if info.Size() > accessMaxFileBytes {
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonTooLarge,
			Detail:   fmt.Sprintf("权限文件体积 %d 字节超过上限 %d", info.Size(), accessMaxFileBytes),
			Blocking: true,
		})
		return out, nil
	}
	raw, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return out, err
	}
	records, err := parseAccessRecords(raw)
	if err != nil {
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonMalformed, Detail: "JSON 结构无法解析", Blocking: true,
		})
		return out, nil
	}
	out.Entries = len(records)
	if len(records) > accessMaxEntries {
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonTooMany,
			Detail:   fmt.Sprintf("记录数 %d 超过上限 %d", len(records), accessMaxEntries),
			Blocking: true,
		})
	}
	out.Findings = append(out.Findings, auditAccessRecords(name, records)...)
	return out, nil
}

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
