package main

import (
	"path/filepath"
)

func saveModAuditSnapshot(path string, snap *ModAuditSnapshot) error {
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	return writePrivateJSONBounded(path, snap, 16<<20)
}

// ---- 对账 ----

// auditModsAgainstBaseline 把当前 mods 目录与基线账本对账，产出差异报告。
// current 为当前快照；baseline 可为 nil（无基线 -> 全量视为新增）。
