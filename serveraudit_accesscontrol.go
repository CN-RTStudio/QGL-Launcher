package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func acInspectOps(audit *AccessControlAudit, dir string) {
	path := filepath.Join(dir, "ops.json")
	body, err := readBoundedFile(path, acMaxJSONBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		audit.add("ops.json", acReasonUnreachable(err), "无法读取 ops.json", true)
		return
	}
	var entries []opEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		audit.add("ops.json", acReasonMalformed, "ops.json 不是合法的操作员列表", true)
		return
	}
	if len(entries) > acMaxEntries {
		audit.add("ops.json", acReasonTooLarge, "操作员条目超过预算", true)
		return
	}
	seenUUID := map[string]int{}
	seenName := map[string]int{}
	for i, entry := range entries {
		if strings.TrimSpace(entry.UUID) == "" || strings.TrimSpace(entry.Name) == "" {
			audit.add("ops.json", acReasonMissingField, fmt.Sprintf("第 %d 项缺少 uuid 或 name", i+1), true)
			continue
		}
		normalized := strings.ToLower(strings.ReplaceAll(entry.UUID, "-", ""))
		if len(normalized) != 32 {
			audit.add("ops.json", acReasonMalformed, fmt.Sprintf("第 %d 项 uuid 长度异常", i+1), true)
		}
		if _, ok := seenUUID[normalized]; ok {
			audit.add("ops.json", acReasonDuplicateEntry, fmt.Sprintf("重复 uuid 条目: %s", entry.Name), false)
		}
		seenUUID[normalized] = i
		lowerName := strings.ToLower(entry.Name)
		if _, ok := seenName[lowerName]; ok {
			audit.add("ops.json", acReasonDuplicateEntry, fmt.Sprintf("重复操作员: %s", entry.Name), false)
		}
		seenName[lowerName] = i
		if entry.Level >= 4 {
			audit.add("ops.json", acReasonOpTooHigh, fmt.Sprintf("%s 拥有 4 级操作员权限", entry.Name), true)
		}
		if entry.Level < 0 || entry.Level > 4 {
			audit.add("ops.json", acReasonMalformed, fmt.Sprintf("%s 操作员等级越界", entry.Name), true)
		}
		if entry.BypassesPlayerCap {
			audit.add("ops.json", acReasonOpTooHigh, fmt.Sprintf("%s 可绕过人数上限", entry.Name), false)
		}
	}
	audit.Sources = append(audit.Sources, "ops.json")
}

func acInspectWhitelist(audit *AccessControlAudit, dir string) {
	path := filepath.Join(dir, "whitelist.json")
	body, err := readBoundedFile(path, acMaxJSONBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		audit.add("whitelist.json", acReasonUnreachable(err), "无法读取 whitelist.json", true)
		return
	}
	var entries []whitelistEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		audit.add("whitelist.json", acReasonMalformed, "whitelist.json 不是合法的白名单", true)
		return
	}
	if len(entries) > acMaxEntries {
		audit.add("whitelist.json", acReasonTooLarge, "白名单条目超过预算", true)
		return
	}
	for i, entry := range entries {
		if strings.TrimSpace(entry.UUID) == "" || strings.TrimSpace(entry.Name) == "" {
			audit.add("whitelist.json", acReasonMissingField, fmt.Sprintf("第 %d 项缺少 uuid 或 name", i+1), true)
		}
	}
	audit.Sources = append(audit.Sources, "whitelist.json")
}
