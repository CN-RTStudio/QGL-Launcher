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
