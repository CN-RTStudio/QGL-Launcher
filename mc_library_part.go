package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

func (a *App) resolveVersionJSON(versionID string) (*VersionJSON, error) {
	// 入口版本 ID 同样来自外部（版本目录扫描 / 前端），必须先收敛成单段安全名，
	// 避免把 "../../x" 之类直接拼进 versions/<id>/<id>.json 造成路径穿越。
	// 版本名允许空格 / 中文等，只拦分隔符、盘符与控制符（见 safeVersionName）。
	safeID := safeVersionName(versionID)
	if safeID == "" {
		return nil, fmt.Errorf("版本 ID 不是合法的单段名称，拒绝解析: %q", versionID)
	}
	return a.resolveVersionJSONSafe(safeID, 0, map[string]bool{})
}

// resolveVersionJSONSafe 在继承深度 / 成环检测下递归解析版本 JSON。
func (a *App) resolveVersionJSONSafe(versionID string, depth int, seen map[string]bool) (*VersionJSON, error) {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)
	jsonPath := filepath.Join(versionDir, versionID+".json")
	if !inspectRegularFile(jsonPath).trustable() {
		jsonFiles, _ := filepath.Glob(filepath.Join(versionDir, "*.json"))
		if len(jsonFiles) > 0 {
			jsonPath = jsonFiles[0]
		}
	}
	jsonData, err := readBoundedFile(jsonPath, maxMetadataJSONBytes)
	if err != nil {
		return nil, fmt.Errorf("未找到或无法读取版本 JSON: %s (%v)", versionDir, err)
	}
	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return nil, fmt.Errorf("解析版本 JSON 失败: %v", err)
	}
	if rawParent := strings.TrimSpace(versionJSON.InheritsFrom); rawParent != "" {
		parentID, perr := validateInheritStep(rawParent, depth, seen)
		if perr != nil {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityCritical, auditActionBlocked,
				"version-manifest", "inheritsFrom: "+perr.Error())
			return nil, perr
		}
		seen[versionID] = true
		parentJSON, perr := a.resolveVersionJSONSafe(parentID, depth+1, seen)
		if perr != nil {
			fmt.Printf("解析父版本 JSON 失败: %v（继续使用当前版本信息）\n", perr)
		} else {
			versionJSON = a.mergeVersionJSON(parentJSON, &versionJSON)
		}
	}
	return &versionJSON, nil
}
