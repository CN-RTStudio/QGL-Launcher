package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func ppValidIPv4(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		value := 0
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
			value = value*10 + int(ch-'0')
		}
		if value > 255 {
			return false
		}
	}
	return true
}

func ppAuditOperators(a *PlayerPrivacyAudit, dir string) {
	data := ppLoadJSON(a, dir, "ops.json")
	if len(data) == 0 {
		return
	}
	var entries []ppOpEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		a.add("ops.json", ppReasonMalformedJSON, "管理员列表不是合法 JSON 数组", true)
		return
	}
	full := 0
	bypass := 0
	bad := 0
	for _, e := range entries {
		if !ppUUIDPattern.MatchString(strings.ToLower(strings.TrimSpace(e.UUID))) {
			bad++
		}
		if e.Level >= 4 {
			full++
		}
		if e.BypassesPlayerLimit {
			bypass++
		}
	}
	if bad > 0 {
		a.add("ops.json", ppReasonBadName, fmt.Sprintf("%d 条管理员条目 UUID 非法", bad), true)
	}
	if full > 0 {
		a.add("ops.json", ppReasonOpLevel, fmt.Sprintf("%d 个管理员拥有 4 级权限", full), false)
	}
	if bypass > 0 {
		a.add("ops.json", ppReasonBypassLimit, fmt.Sprintf("%d 个管理员绕过人数上限", bypass), false)
	}
}
