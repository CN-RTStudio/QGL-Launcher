package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

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
