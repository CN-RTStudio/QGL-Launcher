package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) ToggleMod(modFilePath string, enable bool) error {
	if _, err := os.Stat(modFilePath); err != nil {
		return fmt.Errorf("文件不存在: %s", modFilePath)
	}

	var newPath string
	if enable {
		if strings.HasSuffix(strings.ToLower(modFilePath), ".jar.disabled") {
			newPath = modFilePath[:len(modFilePath)-len(".disabled")]
		} else {
			return nil
		}
	} else {
		if strings.HasSuffix(strings.ToLower(modFilePath), ".jar") {
			newPath = modFilePath + ".disabled"
		} else {
			return nil
		}
	}

	if err := os.Rename(modFilePath, newPath); err != nil {
		return fmt.Errorf("重命名失败: %v", err)
	}

	return nil
}

// ImportMod 导入 Mod 文件
func (a *App) ImportMod(versionID string) error {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 Mod 文件",
		Filters: []runtime.FileFilter{
			{DisplayName: "Mod 文件 (*.jar)", Pattern: "*.jar"},
		},
	})
	if err != nil || path == "" {
		return nil
	}

	mcDir := a.GetMinecraftDir()
	var modsDir string

	if a.isVersionIsolated() && versionID != "" {
		modsDir = filepath.Join(mcDir, "versions", versionID, "mods")
	} else {
		modsDir = filepath.Join(mcDir, "mods")
	}

	if err := os.MkdirAll(modsDir, 0755); err != nil {
		return fmt.Errorf("创建 Mod 目录失败: %v", err)
	}

	src, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("打开源文件失败: %v", err)
	}
	defer src.Close()

	fileName := filepath.Base(path)
	destPath := filepath.Join(modsDir, fileName)

	if _, err := os.Stat(destPath); err == nil {
		return fmt.Errorf("Mod 文件已存在: %s", fileName)
	}

	dst, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("创建目标文件失败: %v", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		os.Remove(destPath)
		return fmt.Errorf("复制文件失败: %v", err)
	}

	return nil
}

// DeleteMod 删除 Mod 文件
