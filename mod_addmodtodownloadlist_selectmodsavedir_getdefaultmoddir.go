package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

)

func (a *App) GetDefaultModDir(versionID string) string {
	mcDir := a.GetMinecraftDir()
	if versionID != "" {
		return filepath.Join(mcDir, "versions", versionID, "mods")
	}
	return filepath.Join(mcDir, "mods")
}

// GetModList 获取指定版本的 Mod 列表
func (a *App) GetModList(versionID string) ([]ModFileInfo, error) {
	mcDir := a.GetMinecraftDir()
	var modsDir string

	if a.isVersionIsolated() && versionID != "" {
		modsDir = filepath.Join(mcDir, "versions", versionID, "mods")
	} else {
		modsDir = filepath.Join(mcDir, "mods")
	}

	mods := []ModFileInfo{}

	entries, err := os.ReadDir(modsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return mods, nil
		}
		return nil, fmt.Errorf("读取 Mod 目录失败: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		lowerName := strings.ToLower(name)

		isEnabled := true
		if strings.HasSuffix(lowerName, ".jar.disabled") {
			isEnabled = false
		} else if !strings.HasSuffix(lowerName, ".jar") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		mods = append(mods, ModFileInfo{
			FileName:  name,
			FilePath:  filepath.Join(modsDir, name),
			IsEnabled: isEnabled,
			FileSize:  info.Size(),
		})
	}

	return mods, nil
}

// ToggleMod 切换 Mod 启用/禁用状态
