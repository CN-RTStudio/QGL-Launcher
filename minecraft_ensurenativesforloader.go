package main

import (
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) ensureNativesForLoader(mcDir string, versionID string, versionDir string, nativesDir string, versionJSON *VersionJSON) {
	// 策略1: 从父版本（原版 MC）的 natives 目录复制
	if versionJSON.InheritsFrom != "" {
		parentNativesDir := filepath.Join(mcDir, "versions", versionJSON.InheritsFrom, versionJSON.InheritsFrom+"-natives")
		if entries, err := os.ReadDir(parentNativesDir); err == nil && len(entries) > 0 {
			fmt.Printf("从父版本复制 natives: %s -> %s\n", parentNativesDir, nativesDir)
			copyDirContents(parentNativesDir, nativesDir)
			return
		}
	}

	// 策略2: 尝试从其他已安装版本中查找匹配的原版 natives
	versionsDir := filepath.Join(mcDir, "versions")
	entries, _ := os.ReadDir(versionsDir)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidateNatives := filepath.Join(versionsDir, entry.Name(), entry.Name()+"-natives")
		if info, err := os.Stat(candidateNatives); err == nil && info.IsDir() {
			if subEntries, err2 := os.ReadDir(candidateNatives); err2 == nil && len(subEntries) > 0 {
				fmt.Printf("从 %s 复制 natives 到 %s\n", candidateNatives, nativesDir)
				copyDirContents(candidateNatives, nativesDir)
				return
			}
		}
	}

	// 策略3: 强制重新解压（合并后的 JSON 应该包含 native 库信息）
	fmt.Printf("尝试重新解压 natives 到: %s\n", nativesDir)
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
}

// copyDirContents 复制目录中的所有文件到目标目录
