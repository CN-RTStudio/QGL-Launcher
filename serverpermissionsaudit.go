package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	smnMaxFindings   = 32
	smnMaxFile       = 256 * 1024
	smnMaxEntries    = 400
	smnMaxInherit    = 3
	smnReasonMiss    = "missing"
	smnReasonLink    = "symlink"
	smnReasonLarge   = "too-large"
	smnReasonRead    = "unreadable"
	smnReasonEmpty   = "empty-config"
	smnReasonDefault = "default-oversized"
	smnReasonWild    = "wildcard-permission"
	smnReasonInherit = "inherit-depth"
	smnReasonNode    = "invalid-node"
	smnReasonCTRL    = "control-characters"
	smnReasonOpGrant = "op-grant"
	smnReasonBusy    = "too-many-entries"
	smnReasonUserOp  = "user-op-default"
)

type PermissionsFinding = auditFinding

type PermissionsAudit struct {
	ServerDir string
	Findings  []PermissionsFinding
}

func (a *PermissionsAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, smnMaxFindings, PermissionsFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PermissionsAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PermissionsFinding) bool { return f.Blocking })
}

func (a *PermissionsAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PermissionsAudit) Describe() string {
	return describeReasonDetail("permissions.yml 未发现风险", a.Findings, 12)
}

type smnEntry struct {
	Path  string
	Value string
}

func smnEntries(text string) []smnEntry {
	type frame struct {
		indent int
		key    string
	}
	stack := make([]frame, 0, 8)
	out := make([]smnEntry, 0, 32)
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		indent := 0
		for indent < len(raw) && raw[indent] == ' ' {
			indent++
		}
		trimmed := strings.TrimSpace(raw)
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent && !strings.HasPrefix(trimmed, "- ") {
			stack = stack[:len(stack)-1]
		}
		if strings.HasPrefix(trimmed, "- ") {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			item = cfgStripQuotes(item)
			path := ""
			if len(stack) > 0 {
				path = stack[len(stack)-1].key
			}
			out = append(out, smnEntry{Path: path, Value: item})
			continue
		}
		sep := strings.Index(trimmed, ":")
		if sep < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:sep])
		value := strings.TrimSpace(trimmed[sep+1:])
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		path := key
		if len(stack) > 0 {
			path = stack[len(stack)-1].key + "." + key
		}
		stack = append(stack, frame{indent: indent, key: path})
		if value != "" {
			out = append(out, smnEntry{Path: path, Value: cfgStripQuotes(value)})
		}
	}
	return out
}

func smnValidNode(node string) bool {
	if node == "" || len(node) > 128 {
		return false
	}
	if strings.HasPrefix(node, ".") || strings.HasSuffix(node, ".") {
		return false
	}
	if strings.Contains(node, "..") || strings.Contains(node, " ") {
		return false
	}
	for _, r := range node {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

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
