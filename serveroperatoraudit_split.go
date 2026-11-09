package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func AuditServerOperators(serverDir string) (*ServerOperatorAudit, error) {
	audit := &ServerOperatorAudit{Files: map[string]int{}}
	for _, name := range operatorFileNames {
		path := filepath.Join(serverDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("读取 %s 失败: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.Findings = append(audit.Findings, OperatorFinding{
				File: name, Reason: operatorReasonSymlink,
				Detail: "权限名单是符号链接", Blocking: true,
			})
			continue
		}
		if !info.Mode().IsRegular() {
			audit.Findings = append(audit.Findings, OperatorFinding{
				File: name, Reason: operatorReasonNotRegular,
				Detail: "权限名单不是普通文件", Blocking: true,
			})
			continue
		}
		if info.Size() > operatorMaxBytes {
			audit.Findings = append(audit.Findings, OperatorFinding{
				File: name, Reason: operatorReasonTooLarge,
				Detail: fmt.Sprintf("超过 %d 字节上限", operatorMaxBytes), Blocking: true,
			})
			continue
		}
		data, err := readBoundedFile(path, auditTextReadMaxBytes)
		if err != nil {
			audit.Findings = append(audit.Findings, OperatorFinding{
				File: name, Reason: operatorReasonUnreadable, Detail: "无法读取文件", Blocking: false,
			})
			continue
		}
		var entries []operatorEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			audit.Findings = append(audit.Findings, OperatorFinding{
				File: name, Reason: operatorReasonBadJSON,
				Detail: "JSON 无法解析，服务器会按空名单处理", Blocking: false,
			})
			continue
		}
		audit.Files[name] = len(entries)
		audit.auditEntries(name, entries)
	}
	return audit, nil
}
