package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) isVersionIsolated() bool { return a.IsVersionIsolation() }
func sanitizePathComponent(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("无效的路径组件: %s", name)
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\:*?"<>|`) {
		return fmt.Errorf("无效的路径组件: %s", name)
	}
	return nil
}

func (a *App) ensureNativesForLoader(mcDir string, versionID string, versionDir string, nativesDir string, versionJSON *VersionJSON) {
	if rawParent := strings.TrimSpace(versionJSON.InheritsFrom); rawParent != "" {
		parentName := safeVersionName(rawParent)
		if parentName != "" {
			parentNativesDir := filepath.Join(mcDir, "versions", parentName, parentName+"-natives")
			if entries, err := os.ReadDir(parentNativesDir); err == nil && len(entries) > 0 {
				fmt.Printf("从父版本复制 natives: %s -> %s\n", parentNativesDir, nativesDir)
				copyDirContents(parentNativesDir, nativesDir)
				return
			}
		}
	}
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
	fmt.Printf("尝试重新解压 natives 到: %s\n", nativesDir)
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
}
