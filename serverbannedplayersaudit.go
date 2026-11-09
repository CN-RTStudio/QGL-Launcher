package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	sbpMaxFindings  = 32
	sbpMaxFile      = 512 * 1024
	sbpMaxEntries   = 2000
	sbpReasonMiss   = "missing"
	sbpReasonLink   = "symlink"
	sbpReasonLarge  = "too-large"
	sbpReasonRead   = "unreadable"
	sbpReasonShape  = "invalid-shape"
	sbpReasonLargeN = "too-many-entries"
	sbpReasonUUID   = "invalid-uuid"
	sbpReasonName   = "invalid-name"
	sbpReasonTime   = "invalid-timestamp"
	sbpReasonReason = "unsafe-reason"
	sbpReasonDup    = "duplicate-uuid"
	sbpReasonPerm   = "many-permanent-bans"
)

type BannedPlayerFinding = auditFinding

type BannedPlayerAudit struct {
	ServerDir string
	Findings  []BannedPlayerFinding
}

func (a *BannedPlayerAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= sbpMaxFindings {
		return
	}
	a.Findings = append(a.Findings, BannedPlayerFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *BannedPlayerAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BannedPlayerFinding) bool { return f.Blocking })
}

func (a *BannedPlayerAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *BannedPlayerAudit) Describe() string {
	return describeAuditFindings("banned-players.json 未发现风险", a.Findings, 12,
		func(f BannedPlayerFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f BannedPlayerFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

type sbpEntry struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Created string `json:"created"`
	Source  string `json:"source"`
	Expires string `json:"expires"`
	Reason  string `json:"reason"`
}

var sbpUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var sbpNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,16}$`)

func sbpParseTime(value string) bool {
	if value == "" || value == "forever" || value == "infinite" {
		return true
	}
	layouts := []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05 -0700"}
	for _, layout := range layouts {
		if _, err := time.Parse(layout, value); err == nil {
			return true
		}
	}
	return false
}

func AuditServerBannedPlayers(serverDir string) *BannedPlayerAudit {
	a := &BannedPlayerAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("banned-players.json", sbpReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "banned-players.json"
	path := filepath.Join(serverDir, rel)
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, sbpReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, sbpReasonLink, "封禁名单是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, sbpReasonMiss, "未找到封禁名单", false)
		return a
	}
	data, err := readBoundedFile(path, sbpMaxFile)
	if err != nil {
		reason := sbpReasonRead
		if err == errLocalFileTooLarge {
			reason = sbpReasonLarge
		}
		a.add(rel, reason, err.Error(), true)
		return a
	}
	var entries []sbpEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		a.add(rel, sbpReasonShape, "JSON 结构非法", true)
		return a
	}
	if len(entries) > sbpMaxEntries {
		a.add(rel, sbpReasonLargeN, fmt.Sprintf("条目数 %d 超过上限", len(entries)), false)
	}
	seen := map[string]bool{}
	permanent := 0
	for i, e := range entries {
		detail := fmt.Sprintf("第 %d 条", i+1)
		uuid := strings.ToLower(strings.TrimSpace(e.UUID))
		if !sbpUUIDPattern.MatchString(uuid) {
			a.add(rel, sbpReasonUUID, detail+" uuid 非法", false)
		} else if seen[uuid] {
			a.add(rel, sbpReasonDup, detail+" uuid 重复", true)
		} else {
			seen[uuid] = true
		}
		if !sbpNamePattern.MatchString(e.Name) {
			a.add(rel, sbpReasonName, detail+" 玩家名非法", false)
		}
		if !sbpParseTime(e.Created) || !sbpParseTime(e.Expires) {
			a.add(rel, sbpReasonTime, detail+" 时间戳非法", false)
		}
		if e.Expires == "" || e.Expires == "forever" || e.Expires == "infinite" {
			permanent++
		}
		if cfgHasControlChars(e.Reason) || cfgHasControlChars(e.Source) {
			a.add(rel, sbpReasonReason, detail+" 附注含控制字符", false)
		}
	}
	if permanent > 50 {
		a.add(rel, sbpReasonPerm, fmt.Sprintf("永久封禁 %d 条", permanent), false)
	}
	return a
}
