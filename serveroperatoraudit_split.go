package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func (a *ServerOperatorAudit) auditEntries(file string, entries []operatorEntry) {
	seenUUID := map[string]int{}
	seenName := map[string]int{}
	for index, entry := range entries {
		label := strings.TrimSpace(entry.Name)
		if label == "" {
			label = fmt.Sprintf("#%d", index+1)
		}
		uuid := strings.ToLower(strings.TrimSpace(entry.UUID))
		if uuid == "" || !operatorValidUUID(uuid) {
			a.Findings = append(a.Findings, OperatorFinding{
				File: file, Entry: label, Reason: operatorReasonBadUUID,
				Detail: "UUID 缺失或格式不是 36 位带连字符的十六进制", Blocking: false,
			})
		} else {
			seenUUID[uuid]++
			if seenUUID[uuid] == 2 {
				a.Findings = append(a.Findings, OperatorFinding{
					File: file, Entry: label, Reason: operatorReasonDuplicate,
					Detail: "同一 UUID 出现多次，权限判定依赖解析顺序", Blocking: false,
				})
			}
		}
		name := strings.ToLower(strings.TrimSpace(entry.Name))
		if name != "" {
			seenName[name]++
			if seenName[name] == 2 {
				a.Findings = append(a.Findings, OperatorFinding{
					File: file, Entry: label, Reason: operatorReasonDuplicate,
					Detail: "同一玩家名出现多次", Blocking: false,
				})
			}
			if containsControlByte(entry.Name) {
				a.Findings = append(a.Findings, OperatorFinding{
					File: file, Entry: label, Reason: operatorReasonBadName,
					Detail: "玩家名包含控制字符", Blocking: false,
				})
			}
		}
		if file == "ops.json" && (entry.Level < 1 || entry.Level > 4) {
			a.Findings = append(a.Findings, OperatorFinding{
				File: file, Entry: label, Reason: operatorReasonBadLevel,
				Detail: fmt.Sprintf("OP 等级 %d 超出原版 1~4 范围", entry.Level), Blocking: false,
			})
		}
	}
}

func operatorValidUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index := 0; index < len(value); index++ {
		ch := value[index]
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if !IsLowerHex(string(ch), 1) {
			return false
		}
	}
	return true
}
