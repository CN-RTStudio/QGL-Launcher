package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func auditAccessFile(serverDir, name string) (AccessFileAudit, error) {
	out := AccessFileAudit{Name: name}
	path := filepath.Join(serverDir, name)
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	out.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		out.Symlink = true
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonSymlink, Detail: "权限文件是符号链接", Blocking: true,
		})
		return out, nil
	}
	if !info.Mode().IsRegular() {
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonNotRegular, Detail: "权限文件不是普通文件", Blocking: true,
		})
		return out, nil
	}
	if info.Size() > accessMaxFileBytes {
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonTooLarge,
			Detail:   fmt.Sprintf("权限文件体积 %d 字节超过上限 %d", info.Size(), accessMaxFileBytes),
			Blocking: true,
		})
		return out, nil
	}
	raw, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return out, err
	}
	records, err := parseAccessRecords(raw)
	if err != nil {
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonMalformed, Detail: "JSON 结构无法解析", Blocking: true,
		})
		return out, nil
	}
	out.Entries = len(records)
	if len(records) > accessMaxEntries {
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonTooMany,
			Detail:   fmt.Sprintf("记录数 %d 超过上限 %d", len(records), accessMaxEntries),
			Blocking: true,
		})
	}
	out.Findings = append(out.Findings, auditAccessRecords(name, records)...)
	return out, nil
}
