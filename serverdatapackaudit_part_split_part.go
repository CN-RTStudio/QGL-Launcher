package main

import (
	"os"
	"path/filepath"
	"strings"
)

func AuditServerDataPacks(serverDir string) DataPackAudit {
	audit := DataPackAudit{Dir: serverDir}
	for _, root := range dpRoots {
		dir := filepath.Join(serverDir, root)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				name := filepath.Join(root, entry.Name())
				audit.Packs = append(audit.Packs, name)
				metaPath := filepath.Join(dir, entry.Name(), "pack.mcmeta")
				data, err := readBoundedFile(metaPath, auditTextReadMaxBytes)
				if err != nil {
					audit.add(name, dpReasonMissingMcmeta, "目录数据包缺少 pack.mcmeta", false)
					continue
				}
				packCheckMeta(&audit, name, data)
				continue
			}
			if !strings.HasSuffix(strings.ToLower(entry.Name()), ".zip") {
				continue
			}
			name := filepath.Join(root, entry.Name())
			audit.Packs = append(audit.Packs, name)
			if len(audit.Packs) > dpMaxPacks {
				audit.add(name, dpReasonTooMany, "数据包数量超过预算", true)
				continue
			}
			packCheckZip(&audit, name, filepath.Join(dir, entry.Name()))
		}
	}
	if len(audit.Findings) == 0 {
		audit.add("", dpReasonOK, "未发现数据包", false)
	}
	return audit
}

func packShorten(value string) string {
	if len(value) > 48 {
		return value[:45] + "..."
	}
	return value
}
