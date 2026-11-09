package main

import (
	"fmt"
	"os"
	"path/filepath"
)

type auditRootScan struct {
	maxFiles      int
	badPathReason string
	missingReason string
	missingDetail string
	tooManyFile   string
	tooManyReason string
	tooManyDetail func(int) string
	okFile        string
	okReason      string
	okDetail      string
}

func scanAuditRoot(serverDir string, spec auditRootScan, collect func(string) []string, inspect func(root, path string), add func(file, reason, detail string, blocking bool), countFindings func() int) string {
	root, err := filepath.Abs(serverDir)
	if err != nil {
		add("server-dir", spec.badPathReason, spec.missingDetail, true)
		return ""
	}
	info, statErr := os.Lstat(root)
	if statErr != nil || !info.IsDir() {
		add("server-dir", spec.missingReason, spec.missingDetail, true)
		return ""
	}
	items := collect(root)
	if len(items) > spec.maxFiles {
		add(spec.tooManyFile, spec.tooManyReason, spec.tooManyDetail(len(items)), false)
		items = items[:spec.maxFiles]
	}
	for _, path := range items {
		inspect(root, path)
	}
	if countFindings() == 0 {
		add(spec.okFile, spec.okReason, spec.okDetail, false)
	}
	return root
}

var pmRootScan = auditRootScan{
	maxFiles:      pmMaxFiles,
	badPathReason: pmReasonUnreadable,
	missingReason: pmReasonMissing,
	missingDetail: "服务器目录不存在",
	tooManyFile:   "permissions",
	tooManyReason: pmReasonTooManyFiles,
	tooManyDetail: func(total int) string { return fmt.Sprintf("权限文件 %d 个超过扫描上限", total) },
	okFile:        "permissions",
	okReason:      pmReasonOK,
	okDetail:      "权限配置未发现通配授予",
}

var yhRootScan = auditRootScan{
	maxFiles:      yhMaxFiles,
	badPathReason: yhReasonUnreadable,
	missingReason: yhReasonUnreadable,
	missingDetail: "服务器目录不存在",
	tooManyFile:   "yaml",
	tooManyReason: yhReasonTooManyFiles,
	tooManyDetail: func(total int) string { return fmt.Sprintf("YAML 文件 %d 个超过扫描上限", total) },
	okFile:        "yaml",
	okReason:      yhReasonOK,
	okDetail:      "YAML 配置均在白名单结构内",
}
