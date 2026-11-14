package main

import (
	"fmt"
	"strings"
)

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
