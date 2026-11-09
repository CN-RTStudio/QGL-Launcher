package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	soaMaxFindings  = 32
	soaMaxFile      = 512 * 1024
	soaMaxOperators = 64
	soaMaxLevel     = 4
	soaBusyOps      = 8
	soaReasonMiss   = "missing"
	soaReasonLink   = "symlink"
	soaReasonLarge  = "too-large"
	soaReasonRead   = "unreadable"
	soaReasonShape  = "invalid-shape"
	soaReasonLargeN = "too-many-operators"
	soaReasonUUID   = "invalid-uuid"
	soaReasonName   = "invalid-name"
	soaReasonLevel  = "invalid-level"
	soaReasonBypass = "invalid-bypass-flag"
	soaReasonDup    = "duplicate-operator"
	soaReasonOwner  = "owner-level-operator"
	soaReasonBusy   = "many-privileged-operators"
	soaReasonEmpty  = "empty-operator-list"
)

type OpsJsonFinding = auditFinding

type OpsJsonAudit struct {
	ServerDir string
	Findings  []OpsJsonFinding
}

type opsJsonEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               *int   `json:"level"`
	BypassesPlayerLimit *bool  `json:"bypassesPlayerLimit"`
}

func (a *OpsJsonAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, soaMaxFindings, OpsJsonFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *OpsJsonAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f OpsJsonFinding) bool { return f.Blocking })
}

func (a *OpsJsonAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *OpsJsonAudit) Describe() string {
	return describeAuditFindings("服务器操作员清单未发现风险", a.Findings, 12,
		func(f OpsJsonFinding) []string {
			return []string{f.File, f.Reason, f.Detail}
		},
		func(f OpsJsonFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

func soaValidUUID(value string) bool {
	if len(value) != 36 && len(value) != 32 {
		return false
	}
	clean := strings.ReplaceAll(value, "-", "")
	if len(clean) != 32 {
		return false
	}
	for _, c := range clean {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func soaValidName(value string) bool {
	return propsValidName(value)
}

func AuditServerOpsJson(serverDir string) *OpsJsonAudit {
	a := &OpsJsonAudit{ServerDir: serverDir}
	const rel = "ops.json"
	if serverDir == "" {
		a.add(".", soaReasonMiss, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", soaReasonLink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, soaReasonLink, "操作员清单为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, soaMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, soaReasonLarge, fmt.Sprintf("操作员清单超过 %d 字节", soaMaxFile), true)
			return a
		}
		a.add(rel, soaReasonRead, "操作员清单不可读", false)
		return a
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		a.add(rel, soaReasonEmpty, "操作员清单为空文件", false)
		return a
	}
	var entries []opsJsonEntry
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
		a.add(rel, soaReasonShape, "操作员清单不是合法的 JSON 数组", true)
		return a
	}
	if len(entries) > soaMaxOperators {
		a.add(rel, soaReasonLargeN, fmt.Sprintf("操作员数量 %d 超过 %d", len(entries), soaMaxOperators), true)
	}
	if len(entries) == 0 {
		a.add(rel, soaReasonEmpty, "操作员清单为空数组", false)
		return a
	}

	seenUUID := make(map[string]bool, len(entries))
	seenName := make(map[string]bool, len(entries))
	privileged := 0
	for i, entry := range entries {
		label := fmt.Sprintf("#%d", i+1)
		if strings.TrimSpace(entry.UUID) == "" {
			a.add(rel, soaReasonUUID, label+" 缺少 uuid", true)
		} else if !soaValidUUID(entry.UUID) {
			a.add(rel, soaReasonUUID, label+" uuid 格式非法", true)
		} else {
			key := strings.ToLower(strings.ReplaceAll(entry.UUID, "-", ""))
			if seenUUID[key] {
				a.add(rel, soaReasonDup, label+" uuid 重复", false)
			}
			seenUUID[key] = true
		}
		if !soaValidName(entry.Name) {
			a.add(rel, soaReasonName, label+" 玩家名非法", true)
		} else {
			key := strings.ToLower(entry.Name)
			if seenName[key] {
				a.add(rel, soaReasonDup, label+" 玩家名重复", false)
			}
			seenName[key] = true
		}
		if entry.Level == nil {
			a.add(rel, soaReasonLevel, label+" 缺少 level 字段", true)
		} else if *entry.Level < 0 || *entry.Level > soaMaxLevel {
			a.add(rel, soaReasonLevel, label+" level 超出 0..4", true)
		} else {
			if *entry.Level >= 2 {
				privileged++
			}
			if *entry.Level == soaMaxLevel {
				a.add(rel, soaReasonOwner, label+" 具备服务器所有权限", false)
			}
		}
		if entry.BypassesPlayerLimit == nil {
			a.add(rel, soaReasonBypass, label+" 缺少 bypassesPlayerLimit 布尔值", false)
		}
	}
	if privileged > soaBusyOps {
		a.add(rel, soaReasonBusy, fmt.Sprintf("%d 名操作员拥有二级以上权限", privileged), false)
	}
	return a
}
