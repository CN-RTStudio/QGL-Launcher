package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func AuditServerWhitelistCoverage(serverDir string) *WhitelistCoverageAudit {
	a := &WhitelistCoverageAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("server.properties", swcMissProps, "未配置服务器目录", false)
		return a
	}
	propsData, err := readBoundedFile(filepath.Join(serverDir, "server.properties"), swcMaxFile)
	if err != nil {
		a.add("server.properties", swcReadProps, "无法读取 server.properties", false)
		return a
	}
	props := pxParseProperties(string(propsData))
	if len(props) == 0 {
		a.add("server.properties", swcReadProps, "属性文件为空", false)
		return a
	}
	white, hasWhite := swcBool(props, "white-list")
	enforce, hasEnforce := swcBool(props, "enforce-whitelist")
	entries, hasFile := swcLoadEntries(serverDir, a)

	if hasEnforce && enforce {
		if !hasWhite || !white {
			a.add("server.properties", swcEnforceBad, "强制白名单已开但白名单本身未启用", true)
		}
		if !hasFile {
			a.add("whitelist.json", swcOnNoFile, "强制白名单却缺少白名单文件", true)
		}
	}
	if hasWhite && white && !hasFile {
		a.add("whitelist.json", swcOnNoFile, "白名单已启用但文件不存在，启动后或被重置", true)
	}
	if hasWhite && !white && hasFile && len(entries) > 0 {
		a.add("whitelist.json", swcOffButList, fmt.Sprintf("白名单关闭但仍有 %d 条记录", len(entries)), false)
	}
	if hasFile {
		seen := make(map[string]int, len(entries))
		for _, entry := range entries {
			name := strings.ToLower(strings.TrimSpace(entry.Name))
			if strings.TrimSpace(entry.UUID) == "" {
				a.add("whitelist.json", swcNoUUID, "条目缺少 UUID: "+entry.Name, false)
			}
			if name != "" {
				seen[name]++
				if seen[name] == 2 {
					a.add("whitelist.json", swcDupName, "重复名称: "+entry.Name, false)
				}
			}
		}
		if ops := swcOpsNames(serverDir); len(ops) > 0 {
			listed := make(map[string]bool, len(entries))
			for _, entry := range entries {
				listed[strings.ToLower(strings.TrimSpace(entry.Name))] = true
			}
			for _, name := range ops {
				if !listed[strings.ToLower(strings.TrimSpace(name))] {
					a.add("whitelist.json", swcOpNotListed, "管理员不在白名单: "+name, false)
				}
			}
		}
	}
	return a
}

const (
	swfMaxFindings = 32
	swfMaxFile     = 512 * 1024
	swfMaxEntries  = 512
	swfReasonMiss  = "missing"
	swfReasonLink  = "symlink"
	swfReasonLarge = "too-large"
	swfReasonRead  = "unreadable"
	swfReasonShape = "invalid-shape"
	swfReasonMany  = "too-many-entries"
	swfReasonUUID  = "invalid-uuid"
	swfReasonName  = "invalid-name"
	swfReasonCtl   = "control-characters"
	swfReasonDup   = "duplicate-entry"
	swfReasonEmpty = "empty-whitelist"
)

type WhitelistFileFinding = auditFinding
type WhitelistFileAudit struct {
	ServerDir string
	Findings  []WhitelistFileFinding
}
type whitelistFileEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

func (a *WhitelistFileAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, swfMaxFindings, WhitelistFileFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WhitelistFileAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WhitelistFileFinding) bool { return f.Blocking })
}

func (a *WhitelistFileAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WhitelistFileAudit) Describe() string {
	return describeFileReasonDetail("服务器白名单文件未发现风险", a.Findings, 12)
}

func swfValidUUID(value string) bool {
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

func swfValidName(value string) bool {
	return propsValidName(value)
}

func AuditServerWhitelistFile(serverDir string) *WhitelistFileAudit {
	a := &WhitelistFileAudit{ServerDir: serverDir}
	const rel = "whitelist.json"
	if serverDir == "" {
		a.add(".", swfReasonMiss, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", swfReasonLink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, swfReasonLink, "白名单文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, swfMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, swfReasonLarge, fmt.Sprintf("白名单文件超过 %d 字节", swfMaxFile), true)
			return a
		}
		a.add(rel, swfReasonRead, "白名单文件不可读", false)
		return a
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		a.add(rel, swfReasonShape, "白名单文件为空", true)
		return a
	}
	var entries []whitelistFileEntry
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
		a.add(rel, swfReasonShape, "白名单文件不是合法的 JSON 数组", true)
		return a
	}
	if len(entries) > swfMaxEntries {
		a.add(rel, swfReasonMany, fmt.Sprintf("条目数量 %d 超过 %d", len(entries), swfMaxEntries), true)
	}
	if len(entries) == 0 {
		a.add(rel, swfReasonEmpty, "白名单开启但条目为空，所有玩家都会被拒绝", false)
		return a
	}

	seen := make(map[string]bool, len(entries))
	for i, entry := range entries {
		label := fmt.Sprintf("#%d", i+1)
		if !swfValidUUID(entry.UUID) {
			a.add(rel, swfReasonUUID, label+" uuid 格式非法", true)
		}
		if strings.ContainsAny(entry.Name, "\x00\r\n\t") {
			a.add(rel, swfReasonCtl, label+" 玩家名含控制字符", true)
			continue
		}
		if !swfValidName(entry.Name) {
			a.add(rel, swfReasonName, label+" 玩家名非法", true)
			continue
		}
		key := strings.ToLower(strings.ReplaceAll(entry.UUID, "-", "")) + "/" + strings.ToLower(entry.Name)
		if seen[key] {
			a.add(rel, swfReasonDup, label+" 与前面的条目重复", false)
		}
		seen[key] = true
	}
	return a
}
