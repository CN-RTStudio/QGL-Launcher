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

func (a *App) buildClasspath(mcDir string, versionID string, versionJSON *VersionJSON) []string {
	var entries []string
	libsDir := filepath.Join(mcDir, "libraries")
	for _, lib := range versionJSON.Libraries {
		if !a.shouldIncludeLib(lib) || lib.Natives != nil {
			continue
		}
		var libPath string
		if lib.Downloads != nil && lib.Downloads.Artifact != nil && lib.Downloads.Artifact.Path != "" {
			safePath := isSafeRelPath(lib.Downloads.Artifact.Path)
			if safePath == "" {
				continue
			}
			libPath = filepath.Join(libsDir, safePath)
		} else if lib.JarPath != "" {
			// lib.JarPath 是镜像 JSON 直接给的相对路径，必须校验，
			// 否则恶意条目可以把 libraries 之外的任意 jar 塞进启动 classpath。
			safeJarPath := isSafeRelPath(lib.JarPath)
			if safeJarPath == "" {
				continue
			}
			libPath = filepath.Join(libsDir, safeJarPath)
		} else if lib.Name != "" {
			libPath = mavenNameToPath(lib.Name, libsDir)
		}
		if libPath == "" {
			continue
		}
		if state := inspectRegularFile(libPath); !state.trustable() {
			if state.Exists {
				recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
					"classpath", describeUntrustedFile(state, libPath))
			}
			continue
		}
		entries = append(entries, libPath)
	}
	// Jar / InheritsFrom 来自外部版本 JSON，会拼进 versions/<name>/<name>.jar，
	// 必须逐个收敛成单段安全名；三者都非法时跳过该 classpath 条目而不是拼出穿越路径。
	jarName := ""
	for _, c := range []string{versionJSON.Jar, versionJSON.InheritsFrom, versionID} {
		if s := safeVersionName(c); s != "" {
			jarName = s
			break
		}
	}
	if jarName != "" {
		versionJar := filepath.Join(mcDir, "versions", jarName, jarName+".jar")
		if !inspectRegularFile(versionJar).trustable() {
			if self := safeVersionName(versionID); self != "" {
				altJar := filepath.Join(mcDir, "versions", self, self+".jar")
				if inspectRegularFile(altJar).trustable() {
					versionJar = altJar
				}
			}
		}
		entries = append(entries, versionJar)
	}
	return entries
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

func (a *App) mergeVersionJSON(parent *VersionJSON, child *VersionJSON) VersionJSON {
	merged := *parent
	if child.ID != "" {
		merged.ID = child.ID
	}
	if child.MainClass != "" {
		merged.MainClass = child.MainClass
	}
	if child.Type != "" {
		merged.Type = child.Type
	}
	if child.ReleaseTime != "" {
		merged.ReleaseTime = child.ReleaseTime
	}
	if child.Jar != "" {
		merged.Jar = child.Jar
	}
	childGroupArtifacts := map[string]bool{}
	for _, lib := range child.Libraries {
		childGroupArtifacts[libGroupArtifact(lib.Name)] = true
	}
	var mergedLibs []Library
	for _, lib := range parent.Libraries {
		if !childGroupArtifacts[libGroupArtifact(lib.Name)] {
			mergedLibs = append(mergedLibs, lib)
		}
	}
	mergedLibs = append(mergedLibs, child.Libraries...)
	merged.Libraries = mergedLibs
	if child.MinecraftArgs != "" {
		merged.MinecraftArgs = child.MinecraftArgs
	}
	if child.Arguments != nil {
		if merged.Arguments == nil {
			merged.Arguments = &ArgumentsObj{}
		}
		if len(child.Arguments.JVM) > 0 {
			merged.Arguments.JVM = append(merged.Arguments.JVM, child.Arguments.JVM...)
		}
		if len(child.Arguments.Game) > 0 {
			merged.Arguments.Game = append(merged.Arguments.Game, child.Arguments.Game...)
		}
	}
	if child.Downloads != nil {
		merged.Downloads = child.Downloads
	}
	if child.AssetIndex != nil {
		merged.AssetIndex = child.AssetIndex
	}
	merged.InheritsFrom = child.InheritsFrom
	return merged
}
