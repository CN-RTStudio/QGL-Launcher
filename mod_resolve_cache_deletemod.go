package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) DeleteMod(modFilePath string) error {
	mcDir := a.GetMinecraftDir()
	// 与 ToggleMod 同一收口：只能删除受管 mods 目录顶层的 .jar/.jar.disabled。
	// 旧实现 PathWithin(mcDir) 允许删除 .minecraft 内任意文件（saves 世界、版本库等）。
	targetAbs, ok := resolveManagedModPath(mcDir, modFilePath)
	if !ok {
		recordSecurityEvent(auditCategoryPermission, auditSeverityWarn, auditActionRejected,
			"DeleteMod", "拒绝删除受管 Mods 目录之外的文件: "+modFilePath)
		return fmt.Errorf("只能删除 Mods 目录内的 .jar 文件")
	}
	if _, err := os.Stat(targetAbs); err != nil {
		return fmt.Errorf("文件不存在: %s", modFilePath)
	}
	return os.Remove(targetAbs)
}

func (a *App) GetModList(versionID string) ([]ModFileInfo, error) {
	if versionID != "" {
		if strings.Contains(versionID, "..") || strings.Contains(versionID, "/") || strings.Contains(versionID, "\\") {
			return nil, fmt.Errorf("版本ID包含非法字符")
		}
	}
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
