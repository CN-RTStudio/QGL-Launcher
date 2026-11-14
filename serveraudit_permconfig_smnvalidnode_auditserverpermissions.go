package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func AuditServerPermissions(serverDir string) *PermissionsAudit {
	a := &PermissionsAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("permissions.yml", smnReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "permissions.yml"
	path := filepath.Join(serverDir, rel)
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, smnReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, smnReasonLink, "权限配置是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, smnReasonMiss, "未找到 permissions.yml", false)
		return a
	}
	data, err := readBoundedFile(path, smnMaxFile)
	if err != nil {
		reason := smnReasonRead
		if err == errLocalFileTooLarge {
			reason = smnReasonLarge
		}
		a.add(rel, reason, err.Error(), true)
		return a
	}
	text := string(data)
	if strings.TrimSpace(text) == "" {
		a.add(rel, smnReasonEmpty, "权限配置为空", false)
		return a
	}
	entries := smnEntries(text)
	if len(entries) == 0 {
		a.add(rel, smnReasonEmpty, "权限配置无法解析", false)
		return a
	}
	if raw, ok := cfgLookup(cfgFlattenYAML(text), "default"); ok {
		switch strings.ToLower(cfgStripQuotes(raw)) {
		case "op", "true", "allow":
			a.add(rel, smnReasonDefault, "默认权限为 "+strings.ToLower(cfgStripQuotes(raw)), true)
		}
	}
	if len(entries) > smnMaxEntries {
		a.add(rel, smnReasonBusy, fmt.Sprintf("条目数 %d 超过 %d", len(entries), smnMaxEntries), false)
	}
	inherit := map[string]int{}
	for _, e := range entries {
		path := e.Path
		value := e.Value
		if path == "" {
			continue
		}
		if cfgHasControlChars(value) {
			a.add(rel, smnReasonCTRL, path, true)
		}
		if strings.Contains(path, "inheritance") || strings.Contains(path, "parent") {
			group := strings.Split(path, ".")[1]
			inherit[group]++
			continue
		}
		if strings.HasSuffix(path, "permissions") || strings.Contains(path, "permissions.") {
			group := ""
			parts := strings.Split(path, ".")
			if len(parts) >= 2 && parts[0] == "groups" {
				group = parts[1]
			}
			if value == "*" || strings.HasPrefix(value, "*") || strings.HasSuffix(value, ".*") {
				a.add(rel, smnReasonWild, path+" → "+value, true)
				continue
			}
			if value == "bukkit.command.op" || strings.HasPrefix(value, "bukkit.command.op.") {
				a.add(rel, smnReasonOpGrant, path+" → "+value, true)
				continue
			}
			if !smnValidNode(value) {
				a.add(rel, smnReasonNode, path+" → "+value, false)
			}
			if group != "" && len(group) > 64 {
				a.add(rel, smnReasonNode, "权限组名过长", false)
			}
			continue
		}
		if strings.HasPrefix(path, "users.") {
			parts := strings.Split(path, ".")
			if len(parts) >= 3 && parts[2] == "default" {
				if strings.EqualFold(value, "op") || strings.EqualFold(value, "true") {
					a.add(rel, smnReasonUserOp, parts[1], true)
				}
			}
		}
	}
	for group, depth := range inherit {
		if depth > smnMaxInherit {
			a.add(rel, smnReasonInherit, fmt.Sprintf("%s 继承 %d 层", group, depth), false)
		}
	}
	return a
}
