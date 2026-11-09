package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func AuditPlayerCache(serverDir string) (PlayerCacheAudit, error) {
	audit := PlayerCacheAudit{Path: filepath.Join(serverDir, playerCacheFileName)}
	info, err := os.Lstat(audit.Path)
	if os.IsNotExist(err) {
		return audit, nil
	}
	if err != nil {
		return audit, err
	}
	audit.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, PlayerCacheFinding{
			Entry: -1, Reason: playerCacheReasonSymlink,
			Detail: "usercache.json 是符号链接", Blocking: true,
		})
		return audit, nil
	}
	if !info.Mode().IsRegular() {
		audit.Findings = append(audit.Findings, PlayerCacheFinding{
			Entry: -1, Reason: playerCacheReasonNotRegular,
			Detail: "usercache.json 不是普通文件", Blocking: true,
		})
		return audit, nil
	}
	if info.Size() > playerCacheMaxBytes {
		audit.Findings = append(audit.Findings, PlayerCacheFinding{
			Entry: -1, Reason: playerCacheReasonTooLarge,
			Detail: fmt.Sprintf("文件 %d 字节超过上限", info.Size()), Blocking: true,
		})
		return audit, nil
	}
	data, err := readBoundedFile(audit.Path, auditTextReadMaxBytes)
	if err != nil {
		audit.Findings = append(audit.Findings, PlayerCacheFinding{
			Entry: -1, Reason: playerCacheReasonUnreadable, Detail: "读取失败", Blocking: false,
		})
		return audit, nil
	}
	var entries []PlayerCacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		audit.Findings = append(audit.Findings, PlayerCacheFinding{
			Entry: -1, Reason: playerCacheReasonBadJSON, Detail: "JSON 解析失败", Blocking: false,
		})
		return audit, nil
	}
	if len(entries) > playerCacheMaxEntries {
		audit.Findings = append(audit.Findings, PlayerCacheFinding{
			Entry: -1, Reason: playerCacheReasonTooMany,
			Detail: fmt.Sprintf("条目数 %d 超过上限", len(entries)), Blocking: true,
		})
		return audit, nil
	}
	uuids := map[string]int{}
	names := map[string]int{}
	now := time.Now()
	for index, entry := range entries {
		audit.Entries++
		uuid := strings.ToLower(strings.TrimSpace(entry.UUID))
		if !IsLowerHex(uuid, 32) {
			audit.Findings = append(audit.Findings, PlayerCacheFinding{
				Entry: index, Reason: playerCacheReasonBadUUID,
				Detail: fmt.Sprintf("uuid %q 不是 32 位十六进制", entry.UUID), Blocking: false,
			})
		} else if previous, exists := uuids[uuid]; exists {
			audit.Findings = append(audit.Findings, PlayerCacheFinding{
				Entry: index, Reason: playerCacheReasonDuplicate,
				Detail: fmt.Sprintf("uuid 与 #%d 重复", previous), Blocking: false,
			})
		} else {
			uuids[uuid] = index
		}
		if !playerNameValid(entry.Name) {
			audit.Findings = append(audit.Findings, PlayerCacheFinding{
				Entry: index, Reason: playerCacheReasonBadName,
				Detail: fmt.Sprintf("玩家名 %q 不符合 3-16 位字母数字下划线规则", entry.Name), Blocking: false,
			})
		} else if previous, exists := names[strings.ToLower(entry.Name)]; exists {
			audit.Findings = append(audit.Findings, PlayerCacheFinding{
				Entry: index, Reason: playerCacheReasonBadName,
				Detail: fmt.Sprintf("玩家名与 #%d 重复", previous), Blocking: false,
			})
		} else {
			names[strings.ToLower(entry.Name)] = index
		}
		if strings.TrimSpace(entry.ExpiresOn) == "" {
			continue
		}
		expiry, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(entry.ExpiresOn))
		if parseErr != nil {
			audit.Findings = append(audit.Findings, PlayerCacheFinding{
				Entry: index, Reason: playerCacheReasonBadExpiry,
				Detail: fmt.Sprintf("到期时间 %q 无法解析", entry.ExpiresOn), Blocking: false,
			})
			continue
		}
		if expiry.Before(now) {
			audit.Expired++
		}
	}
	return audit, nil
}
