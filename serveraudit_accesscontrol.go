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

func acInspectBans(audit *AccessControlAudit, dir, name string) {
	path := filepath.Join(dir, name)
	body, err := readBoundedFile(path, acMaxJSONBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		audit.add(name, acReasonUnreachable(err), "无法读取封禁列表", true)
		return
	}
	var entries []bannedEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		audit.add(name, acReasonMalformed, "封禁列表不是合法 JSON", true)
		return
	}
	for i, entry := range entries {
		identifier := strings.TrimSpace(entry.UUID)
		if identifier == "" {
			identifier = strings.TrimSpace(entry.IP)
		}
		if identifier == "" {
			audit.add(name, acReasonMissingField, fmt.Sprintf("第 %d 项缺少 uuid 与 ip", i+1), true)
		}
		if strings.Contains(entry.IP, "*") {
			audit.add(name, acReasonMalformed, "封禁条目使用通配 IP，可能误封整段地址", false)
		}
	}
	audit.Sources = append(audit.Sources, name)
}

func acInspectProperties(audit *AccessControlAudit, dir string) {
	path := filepath.Join(dir, "server.properties")
	body, err := readBoundedFile(path, acMaxJSONBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		audit.add("server.properties", acReasonUnreachable(err), "无法读取服务端属性", true)
		return
	}
	audit.Sources = append(audit.Sources, "server.properties")
	values := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		values[key] = strings.TrimSpace(line[eq+1:])
	}
	if mode, ok := values["online-mode"]; ok && strings.EqualFold(mode, "false") {
		audit.add("server.properties", acReasonOfflineMode, "online-mode=false 允许伪造用户名登录", true)
	}
	if white, ok := values["white-list"]; ok && strings.EqualFold(white, "false") {
		audit.add("server.properties", acReasonWhitelistOff, "白名单已关闭", false)
	}
	if enforce, ok := values["enforce-whitelist"]; ok && strings.EqualFold(enforce, "false") {
		audit.add("server.properties", acReasonWhitelistOff, "白名单未强制生效", false)
	} else if !ok {
		if white, ok2 := values["white-list"]; ok2 && strings.EqualFold(white, "true") {
			audit.add("server.properties", acReasonWhitelistOff, "启用白名单但未设置 enforce-whitelist", false)
		}
	}
}

func acReasonUnreachable(err error) string {
	if strings.Contains(err.Error(), "符号链接") {
		return acReasonSymlink
	}
	if strings.Contains(err.Error(), "体积") {
		return acReasonTooLarge
	}
	return acReasonUnreadable
}

func AuditServerAccessControl(serverDir string) AccessControlAudit {
	audit := AccessControlAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("", acReasonMissing, "服务器目录不存在", true)
		return audit
	}
	acInspectProperties(&audit, serverDir)
	acInspectOps(&audit, serverDir)
	acInspectWhitelist(&audit, serverDir)
	acInspectBans(&audit, serverDir, "banned-players.json")
	acInspectBans(&audit, serverDir, "banned-ips.json")
	if len(audit.Sources) == 0 {
		audit.add("", acReasonMissing, "未发现访问控制配置", false)
	}
	if len(audit.Findings) == 0 {
		audit.add("", acReasonOK, "访问控制配置未发现风险", false)
	}
	return audit
}

func (a AccessControlAudit) Describe() string {
	return describeTaggedFindings("访问控制未发现风险", a.Findings, acReasonOK, "server", acMaxFindings,
		func(f AccessControlFinding) string { return f.Reason },
		func(f AccessControlFinding) string { return f.File },
		func(f AccessControlFinding) string { return f.Detail })
}

func (a *AccessControlAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, acMaxFindings, AccessControlFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

type opEntry struct {
	UUID              string `json:"uuid"`
	Name              string `json:"name"`
	Level             int    `json:"level"`
	BypassesPlayerCap bool   `json:"bypassesPlayerLimit"`
}

type whitelistEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type bannedEntry struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	Created string `json:"created"`
}
