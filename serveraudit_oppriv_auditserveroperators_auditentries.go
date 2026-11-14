package main

import (
	"fmt"
	"strings"
)

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
