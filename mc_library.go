package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) shouldIncludeLib(lib Library) bool {
	// 库规则统一走 ruleengine：按 Mojang 语义评估 os.name/arch/version 与 features，
	// 不再只判 os.name=="windows"（旧逻辑会误选 osx/linux 专属库、忽略架构与版本）。
	return libraryRulesAllow(lib.Rules, currentRuleEnv())
}

func libGroupArtifact(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) >= 2 {
		return parts[0] + ":" + parts[1]
	}
	return name
}

// isValidMavenToken 校验 Maven 坐标中的单个片段（groupId 段 / artifactId /
// version / classifier）。版本 JSON 来自镜像站，属于不可信输入：只要片段里出现
// 路径分隔符、盘符、".." 或 Maven 坐标不允许的空白 / 控制字符，就判为非法，
// 防止恶意坐标经 mavenNameToPath 拼出逃逸 libraries 目录的路径。
func isValidMavenToken(token string) bool {
	if token == "" || token == "." || token == ".." {
		return false
	}
	if len(token) > 255 {
		return false
	}
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			// 字母数字
		case strings.ContainsRune("-_.@+", r):
			// Maven 常见合法字符
		default:
			return false
		}
	}
	return true
}

func mavenNameToPath(name string, libsDir string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}
	// 坐标的每一段都必须是干净的 Maven token；groupId 的每个 "." 分段也要
	// 单独校验，否则 "..\.." 之类会在 ReplaceAll 之后变成路径穿越。
	groupParts := strings.Split(parts[0], ".")
	for _, seg := range groupParts {
		if !isValidMavenToken(seg) {
			return ""
		}
	}
	artifact, version := parts[1], parts[2]
	if !isValidMavenToken(artifact) || !isValidMavenToken(version) {
		return ""
	}
	classifier := ""
	if len(parts) >= 4 {
		if !isValidMavenToken(parts[3]) {
			return ""
		}
		classifier = "-" + parts[3]
	}
	group := strings.Join(groupParts, string(os.PathSeparator))
	fileName := fmt.Sprintf("%s-%s%s.jar", artifact, version, classifier)
	rel := filepath.Join(group, artifact, version, fileName)
	// 拼好后再用统一的相对路径校验兜底，确保结果一定在 libraries 内。
	if isSafeRelPath(rel) == "" {
		return ""
	}
	return filepath.Join(libsDir, rel)
}

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
