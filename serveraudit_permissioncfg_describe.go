package main

import (
	"os"
	"path/filepath"
	"sort"
)

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
