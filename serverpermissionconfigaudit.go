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
	return describeTaggedFindings("权限配置未发现越权授予", a.Findings, pmReasonOK, "permissions", pmMaxFindings,
		func(f PermissionConfigFinding) string { return f.Reason },
		func(f PermissionConfigFinding) string { return f.File },
		func(f PermissionConfigFinding) string { return f.Detail })
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
	rel, data, ok := inspectAuditTextFile(a.add, &a.Files, root, path, pmFileCheck)
	if !ok {
		return
	}
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
	if root := scanAuditRoot(serverDir, pmRootScan, pmCollect, func(root, path string) { pmInspectFile(&audit, root, path) }, audit.add, func() int { return len(audit.Findings) }); root != "" {
		audit.Dir = root
	}
	return audit
}
