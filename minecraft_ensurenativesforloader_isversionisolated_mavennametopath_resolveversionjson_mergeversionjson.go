package main

import (

)

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

