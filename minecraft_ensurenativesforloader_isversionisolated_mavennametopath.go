package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

)

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

