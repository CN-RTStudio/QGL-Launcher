package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	accessReasonOK         = "ok"
	accessReasonSymlink    = "symlink"
	accessReasonNotRegular = "not-regular"
	accessReasonTooLarge   = "too-large"
	accessReasonMalformed  = "malformed"
	accessReasonTooMany    = "too-many"
	accessReasonBadEntry   = "bad-entry"
	accessReasonDuplicate  = "duplicate"
	accessMaxFileBytes     = 4 << 20
	accessMaxEntries       = 512
	accessMaxNameRunes     = 64
	accessMinOpsLevel      = 1
	accessMaxOpsLevel      = 4
)

var accessFileNames = []string{
	"ops.json",
	"whitelist.json",
	"banned-players.json",
	"banned-ips.json",
}

type AccessFinding struct {
	File     string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

type AccessFileAudit struct {
	Name     string
	Present  bool
	Symlink  bool
	Entries  int
	Findings []AccessFinding
}

type ServerAccessAudit struct {
	Dir      string
	Files    []AccessFileAudit
	Findings []AccessFinding
}

type accessRecord struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Level   int    `json:"level"`
	IP      string `json:"ip"`
	Expires string `json:"expires"`
}

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
