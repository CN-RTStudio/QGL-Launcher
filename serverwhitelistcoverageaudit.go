package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	swcMaxFindings = 24
	swcMaxFile     = 512 * 1024
	swcMissProps   = "properties-missing"
	swcReadProps   = "properties-unreadable"
	swcOffButList  = "whitelist-off-with-entries"
	swcOnNoFile    = "whitelist-enabled-without-file"
	swcEnforceBad  = "enforce-whitelist-without-whitelist"
	swcBadJSON     = "whitelist-json-invalid"
	swcNoUUID      = "whitelist-entry-without-uuid"
	swcDupName     = "whitelist-duplicate-name"
	swcOpNotListed = "operator-not-whitelisted"
	swcLink        = "whitelist-symlink"
)

type WhitelistCoverageFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type WhitelistCoverageAudit struct {
	ServerDir string
	Findings  []WhitelistCoverageFinding
}

func (a *WhitelistCoverageAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= swcMaxFindings {
		return
	}
	a.Findings = append(a.Findings, WhitelistCoverageFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WhitelistCoverageAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WhitelistCoverageFinding) bool { return f.Blocking })
}

func (a *WhitelistCoverageAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WhitelistCoverageAudit) Describe() string {
	return describeAuditFindings("白名单覆盖检查通过", a.Findings, 12,
		func(f WhitelistCoverageFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f WhitelistCoverageFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

type swcEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

func swcBool(props map[string]string, key string) (bool, bool) {
	return propsBoolValue(props, key)
}

func swcLoadEntries(serverDir string, a *WhitelistCoverageAudit) ([]swcEntry, bool) {
	path := filepath.Join(serverDir, "whitelist.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add("whitelist.json", swcReadProps, err.Error(), true)
		return nil, false
	}
	if link {
		a.add("whitelist.json", swcLink, "白名单文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, swcMaxFile)
	if err != nil {
		a.add("whitelist.json", swcReadProps, err.Error(), true)
		return nil, false
	}
	var entries []swcEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		a.add("whitelist.json", swcBadJSON, err.Error(), true)
		return nil, false
	}
	return entries, true
}

func swcOpsNames(serverDir string) []string {
	data, err := readBoundedFile(filepath.Join(serverDir, "ops.json"), swcMaxFile)
	if err != nil {
		return nil
	}
	var ops []swcEntry
	if err := json.Unmarshal(data, &ops); err != nil {
		return nil
	}
	names := make([]string, 0, len(ops))
	for _, op := range ops {
		if name := strings.TrimSpace(op.Name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

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
