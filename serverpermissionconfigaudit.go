package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	pmReasonOK            = "ok"
	pmReasonMissing       = "missing"
	pmReasonSymlink       = "symlink"
	pmReasonTooLarge      = "too-large"
	pmReasonWorldWritable = "world-writable"
	pmReasonUnreadable    = "unreadable"
	pmReasonWildcardGrant = "wildcard-grant"
	pmReasonDefaultOp     = "default-op"
	pmReasonDefaultAllow  = "default-allow"
	pmReasonOpCommand     = "op-command-grant"
	pmReasonUnknownNode   = "unknown-plugin-node"
	pmReasonTooManyFiles  = "file-overflow"

	pmMaxFileBytes = 512 << 10
	pmMaxFiles     = 24
	pmMaxFindings  = 48
)

var pmCandidateFiles = []string{
	"permissions.yml",
	"config/permissions.yml",
	"plugins/PluginPermissions/permissions.yml",
}

var pmDangerousNodes = []string{
	"bukkit.command.op",
	"minecraft.command.op",
	"bukkit.command.stop",
	"bukkit.command.reload",
	"essentials.give",
	"worldedit.*",
}

type PermissionConfigFinding = auditFinding

type PermissionConfigAudit struct {
	Dir      string
	Files    []string
	Findings []PermissionConfigFinding
}

func (a PermissionConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PermissionConfigFinding) bool { return f.Blocking })
}

func (a PermissionConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PermissionConfigFinding) bool { return !f.Blocking && f.Reason != pmReasonOK })
}

func (a PermissionConfigAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == pmReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "permissions"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= pmMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "权限配置未发现越权授予"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *PermissionConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pmMaxFindings, PermissionConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func pmCollect(root string) []string {
	found := []string{}
	for _, name := range pmCandidateFiles {
		path := filepath.Join(root, filepath.FromSlash(name))
		if _, err := os.Lstat(path); err == nil {
			found = append(found, path)
		}
	}
	pluginsDir := filepath.Join(root, "plugins")
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return found
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		for _, name := range []string{"permissions.yml", "permissions.yaml"} {
			path := filepath.Join(pluginsDir, entry.Name(), name)
			if _, err := os.Lstat(path); err == nil {
				found = append(found, path)
			}
		}
	}
	sort.Strings(found)
	return found
}

func pmInspectFile(a *PermissionConfigAudit, root, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	rel, relErr := filepath.Rel(root, path)
	if relErr != nil {
		rel = filepath.Base(path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(rel, pmReasonSymlink, "权限配置是符号链接", true)
		return
	}
	if info.Size() > pmMaxFileBytes {
		a.add(rel, pmReasonTooLarge, "权限配置超过体积预算", true)
		return
	}
	if info.Mode().Perm()&0o022 != 0 {
		a.add(rel, pmReasonWorldWritable, "权限配置可被其他用户改写", true)
	}
	data, readErr := readBoundedFile(path, pmMaxFileBytes)
	if readErr != nil {
		a.add(rel, pmReasonUnreadable, "权限配置不可读", true)
		return
	}
	a.Files = append(a.Files, rel)
	pmScanText(a, rel, string(data))
}

func pmScanText(a *PermissionConfigAudit, rel, text string) {
	lines := strings.Split(text, "\n")
	wildcard := 0
	defaultOp := 0
	defaultAllow := 0
	opCommand := 0
	unknown := 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "- ") || strings.HasPrefix(lower, "\"") {
			node := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(lower, "- "), "\""))
			node = strings.Trim(node, "\"'")
			if node == "*" || strings.HasSuffix(node, ":*") {
				wildcard++
			}
			if node == "*:*" || node == "bukkit.*" || node == "minecraft.*" {
				wildcard++
			}
			for _, danger := range pmDangerousNodes {
				if node == danger {
					opCommand++
				}
			}
			if strings.Contains(node, "command.") && strings.Contains(node, "op") {
				opCommand++
			}
			continue
		}
		colon := strings.Index(lower, ":")
		if colon <= 0 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(lower[:colon]), "\"'")
		value := strings.Trim(strings.TrimSpace(lower[colon+1:]), "\"'")
		switch key {
		case "default":
			switch value {
			case "op":
				defaultOp++
			case "true", "yes", "allow":
				defaultAllow++
			}
		case "*":
			wildcard++
		case "permission", "node":
			if value == "*" {
				wildcard++
			}
		}
		if key == "description" && strings.Contains(value, "unknown") {
			unknown++
		}
	}
	if wildcard > 0 {
		a.add(rel, pmReasonWildcardGrant, fmt.Sprintf("%d 处通配权限授予", wildcard), true)
	}
	if defaultOp > 0 {
		a.add(rel, pmReasonDefaultOp, fmt.Sprintf("%d 个节点默认授予 op", defaultOp), false)
	}
	if defaultAllow > 0 {
		a.add(rel, pmReasonDefaultAllow, fmt.Sprintf("%d 个节点默认对所有玩家开放", defaultAllow), false)
	}
	if opCommand > 0 {
		a.add(rel, pmReasonOpCommand, fmt.Sprintf("%d 处命令类权限越权授予", opCommand), false)
	}
	if unknown > 0 {
		a.add(rel, pmReasonUnknownNode, fmt.Sprintf("%d 个节点来源未标注", unknown), false)
	}
}

func AuditServerPermissionConfig(serverDir string) PermissionConfigAudit {
	audit := PermissionConfigAudit{Dir: serverDir}
	root, err := filepath.Abs(serverDir)
	if err != nil {
		audit.add("server-dir", pmReasonUnreadable, "无法解析服务器目录", true)
		return audit
	}
	audit.Dir = root
	info, statErr := os.Lstat(root)
	if statErr != nil || !info.IsDir() {
		audit.add("server-dir", pmReasonMissing, "服务器目录不存在", true)
		return audit
	}
	files := pmCollect(root)
	if len(files) > pmMaxFiles {
		audit.add("permissions", pmReasonTooManyFiles, fmt.Sprintf("权限文件 %d 个超过扫描上限", len(files)), false)
		files = files[:pmMaxFiles]
	}
	for _, path := range files {
		pmInspectFile(&audit, root, path)
	}
	if len(audit.Findings) == 0 {
		audit.add("permissions", pmReasonOK, "权限配置未发现通配授予", false)
	}
	return audit
}
