package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

)

func (a *App) isVersionIsolated() bool {
	return a.IsVersionIsolation()
}

// buildClasspath 构建类路径（参考 PCL 的 McLibListGetWithJson + McLaunchArgumentsReplace）
func (a *App) buildClasspath(mcDir string, versionID string, versionJSON *VersionJSON) []string {
	var classpathEntries []string
	libsDir := filepath.Join(mcDir, "libraries")

	for _, lib := range versionJSON.Libraries {
		// 1. 检查 rules（跳过不适用于当前平台的库）
		if !a.shouldIncludeLib(lib) {
			continue
		}

		// 2. 跳过 natives 库（natives 不加入 classpath）
		if lib.Natives != nil {
			continue
		}

		// 3. 确定库文件路径
		var libPath string

		// 优先使用 downloads.artifact.path
		if lib.Downloads != nil && lib.Downloads.Artifact != nil && lib.Downloads.Artifact.Path != "" {
			libPath = filepath.Join(libsDir, lib.Downloads.Artifact.Path)
		} else if lib.JarPath != "" {
			// 有些库直接提供 path 字段
			libPath = filepath.Join(libsDir, lib.JarPath)
		} else if lib.Name != "" {
			// 从 Maven 坐标推算路径（参考 PCL 的 McLibGet）
			libPath = mavenNameToPath(lib.Name, libsDir)
		}

		if libPath == "" {
			continue
		}

		// 4. 检查文件是否存在
		if _, err := os.Stat(libPath); err != nil {
			fmt.Printf("类路径库文件不存在(跳过): %s\n", libPath)
			continue
		}
		classpathEntries = append(classpathEntries, libPath)
	}

	// 5. 添加游戏主 jar（classpath 的最后一个条目）
	// 参考 PCL 的 McLibListGet：jar 字段优先，否则沿 inheritsFrom 链查找原版
	jarName := versionJSON.Jar
	if jarName == "" {
		// 沿 inheritsFrom 链查找原版版本名
		jarName = versionJSON.InheritsFrom
	}
	if jarName == "" {
		jarName = versionID
	}
	versionJar := filepath.Join(mcDir, "versions", jarName, jarName+".jar")

	// 如果 jar 不存在，尝试在当前版本目录中查找
	if _, err := os.Stat(versionJar); err != nil {
		altJar := filepath.Join(mcDir, "versions", versionID, versionID+".jar")
		if _, err2 := os.Stat(altJar); err2 == nil {
			versionJar = altJar
		}
	}

	classpathEntries = append(classpathEntries, versionJar)

	return classpathEntries
}

// shouldIncludeLib 检查库是否应该包含（参考 PCL 的 McJsonRuleCheck）
func (a *App) shouldIncludeLib(lib Library) bool {
	if len(lib.Rules) == 0 {
		return true // 没有 rules，默认包含
	}

	allow := false
	for _, rule := range lib.Rules {
		osMatch := true
		if rule.OS != nil {
			osMatch = rule.OS.Name == "windows"
		}

		if rule.Action == "allow" {
			if osMatch {
				allow = true
			}
		} else if rule.Action == "disallow" {
			if osMatch {
				allow = false
			}
		}
	}

	return allow
}

// libGroupArtifact 从 Maven 坐标中提取 group:artifact（不含版本号）
// 例如 "org.apache.logging.log4j:log4j-core:2.17.1" -> "org.apache.logging.log4j:log4j-core"
func libGroupArtifact(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) >= 2 {
		return parts[0] + ":" + parts[1]
	}
	return name
}

// mavenNameToPath 从 Maven 坐标推算库文件路径（参考 PCL 的 McLibGet）
// Maven 坐标格式: group:artifact:version 或 group:artifact:version:classifier
// 路径格式: group/artifact/version/artifact-version(-classifier).jar
func mavenNameToPath(name string, libsDir string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}

	group := strings.ReplaceAll(parts[0], ".", string(os.PathSeparator))
	artifact := parts[1]
	version := parts[2]
	classifier := ""
	if len(parts) >= 4 {
		classifier = "-" + parts[3]
	}

	// 文件名: artifact-version(-classifier).jar
	fileName := fmt.Sprintf("%s-%s%s.jar", artifact, version, classifier)

	// 完整路径: libsDir/group/artifact/version/fileName
	return filepath.Join(libsDir, group, artifact, version, fileName)
}

// resolveVersionJSON 解析版本 JSON，处理 inheritsFrom 继承关系
// Forge/Fabric/NeoForge/OptiFine 版本都通过 inheritsFrom 引用原版版本
// 需要合并父版本的 libraries、downloads、assetIndex 等信息
func (a *App) resolveVersionJSON(versionID string) (*VersionJSON, error) {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)

	// 查找版本 JSON 文件（文件名可能与文件夹名不同）
	jsonPath := filepath.Join(versionDir, versionID+".json")
	if _, err := os.Stat(jsonPath); err != nil {
		// 尝试查找文件夹中的任意 JSON 文件
		jsonFiles, _ := filepath.Glob(filepath.Join(versionDir, "*.json"))
		if len(jsonFiles) > 0 {
			jsonPath = jsonFiles[0]
		} else {
			return nil, fmt.Errorf("未找到版本 JSON: %s", versionDir)
		}
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("读取版本 JSON 失败: %v", err)
	}

	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return nil, fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	// 处理 inheritsFrom
	if versionJSON.InheritsFrom != "" {
		parentJSON, err := a.resolveVersionJSON(versionJSON.InheritsFrom)
		if err != nil {
			fmt.Printf("解析父版本 JSON 失败: %v（将继续使用当前版本信息）\n", err)
		} else {
			// 合并父版本信息
			versionJSON = a.mergeVersionJSON(parentJSON, &versionJSON)
		}
	}

	return &versionJSON, nil
}

// mergeVersionJSON 合并父版本和子版本 JSON
// 子版本（Forge/Fabric）的字段覆盖父版本（原版）的字段
func (a *App) mergeVersionJSON(parent *VersionJSON, child *VersionJSON) VersionJSON {
	merged := *parent // 以父版本为基础

	// 子版本覆盖的字段
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

	// 合并 libraries：父版本 + 子版本（按 group:artifact 去重）
	// 规则：子版本的库覆盖父版本中相同 group:artifact 的所有条目
	// 这样 Forge 的 log4j 会覆盖原版的 log4j，而 LWJGL 等原版独有库全部保留
	childGroupArtifacts := map[string]bool{}
	for _, lib := range child.Libraries {
		ga := libGroupArtifact(lib.Name)
		if ga != "" {
			childGroupArtifacts[ga] = true
		}
	}
	var mergedLibs []Library
	for _, lib := range parent.Libraries {
		ga := libGroupArtifact(lib.Name)
		if ga != "" && childGroupArtifacts[ga] {
			continue // 子版本有同名 group:artifact，跳过父版本
		}
		mergedLibs = append(mergedLibs, lib)
	}
	mergedLibs = append(mergedLibs, child.Libraries...)
	merged.Libraries = mergedLibs

	// 合并 arguments
	if child.MinecraftArgs != "" {
		merged.MinecraftArgs = child.MinecraftArgs
	}
	if child.Arguments != nil {
		if merged.Arguments == nil {
			merged.Arguments = &ArgumentsObj{}
		}
		// 合并 JVM 参数：父版本 + 子版本
		if len(child.Arguments.JVM) > 0 {
			merged.Arguments.JVM = append(merged.Arguments.JVM, child.Arguments.JVM...)
		}
		// 合并 Game 参数：父版本 + 子版本
		if len(child.Arguments.Game) > 0 {
			merged.Arguments.Game = append(merged.Arguments.Game, child.Arguments.Game...)
		}
	}

	// 子版本有自己的 downloads 时覆盖
	if child.Downloads != nil {
		merged.Downloads = child.Downloads
	}
	// 子版本有自己的 assetIndex 时覆盖
	if child.AssetIndex != nil {
		merged.AssetIndex = child.AssetIndex
	}

	// 保留 inheritsFrom 用于参考
	merged.InheritsFrom = child.InheritsFrom

	return merged
}

