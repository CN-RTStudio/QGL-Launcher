package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func adAuditPayload(audit *AdvancementAudit, dir, name string, raw []byte) {
	var decoded struct {
		Criteria     map[string]json.RawMessage `json:"criteria"`
		Requirements json.RawMessage            `json:"requirements"`
		Parent       string                     `json:"parent"`
		Rewards      struct {
			Loot    []string `json:"loot"`
			Recipes []string `json:"recipes"`
		} `json:"rewards"`
		Display struct {
			Icon  json.RawMessage `json:"icon"`
			Title json.RawMessage `json:"title"`
			Frame string          `json:"frame"`
		} `json:"display"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		if adJSONDepth(raw) > adMaxDepth {
			audit.add(dir, name, adReasonDeepNesting, fmt.Sprintf("嵌套深度 %d", adJSONDepth(raw)), true)
			return
		}
		audit.add(dir, name, adReasonMalformedJSON, "进度文件无法解析", false)
		return
	}
	if len(decoded.Criteria) > adMaxCriteria {
		audit.add(dir, name, adReasonTooManyCriteria, fmt.Sprintf("criteria %d 条", len(decoded.Criteria)), false)
	}
	for _, loot := range decoded.Rewards.Loot {
		if adUnsafeResource(loot) {
			audit.add(dir, name, adReasonLootTraversal, "奖励战利品路径异常 "+loot, true)
		}
	}
	for _, recipe := range decoded.Rewards.Recipes {
		if adUnsafeResource(recipe) {
			audit.add(dir, name, adReasonLootTraversal, "奖励配方路径异常 "+recipe, true)
		}
	}
	icon := strings.Trim(string(decoded.Display.Icon), `"`)
	if icon != "" && adUnsafeResource(icon) {
		audit.add(dir, name, adReasonIconTraversal, "图标路径异常 "+icon, true)
	}
	if decoded.Parent != "" && adUnsafeResource(decoded.Parent) {
		audit.add(dir, name, adReasonParentEscape, "父进度路径异常 "+decoded.Parent, false)
	}
	for _, key := range adDuplicateKeys(raw) {
		audit.add(dir, name, adReasonDuplicateKey, "重复键 "+key, false)
	}
}
