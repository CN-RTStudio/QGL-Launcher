package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
