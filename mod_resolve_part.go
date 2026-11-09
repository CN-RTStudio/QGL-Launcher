package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"os"
	"path/filepath"
	"strings"
)

type ModDependencyResult struct {
	ProjectID      string `json:"projectId"`
	ProjectName    string `json:"projectName"`
	IconURL        string `json:"iconUrl"`
	VersionID      string `json:"versionId"`
	DependencyType string `json:"dependencyType"`
}

// SelectModSaveDir 弹出选择 Mod 保存目录对话框
func (a *App) SelectModSaveDir() (string, error) {
	path, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 Mod 保存位置",
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// GetDefaultModDir 获取默认 Mod 目录
func (a *App) GetDefaultModDir(versionID string) string {
	mcDir := a.GetMinecraftDir()
	if versionID != "" && !strings.Contains(versionID, "..") && !strings.Contains(versionID, "/") && !strings.Contains(versionID, "\\") {
		return filepath.Join(mcDir, "versions", versionID, "mods")
	}
	return filepath.Join(mcDir, "mods")
}

// GetModList 获取指定版本的 Mod 列表
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

// ToggleMod 切换 Mod 启用/禁用状态
func (a *App) ToggleMod(modFilePath string, enable bool) error {
	mcDir := a.GetMinecraftDir()
	// 只允许操作“受管 mods 目录”（全局 mods 或版本隔离 mods）顶层的 .jar/.jar.disabled。
	// 旧实现只判定 PathWithin(mcDir)，等于放权整个 .minecraft，渲染层可借改名禁用
	// libraries/versions 里的任意 jar（破坏依赖）；这里收口到受管集合。
	curAbs, ok := resolveManagedModPath(mcDir, modFilePath)
	if !ok {
		recordSecurityEvent(auditCategoryPermission, auditSeverityWarn, auditActionRejected,
			"ToggleMod", "拒绝切换受管 Mods 目录之外的文件: "+modFilePath)
		return fmt.Errorf("只能切换 Mods 目录内的 .jar 文件")
	}
	if _, err := os.Stat(curAbs); err != nil {
		return fmt.Errorf("文件不存在: %s", modFilePath)
	}

	var newPath string
	if enable {
		if strings.HasSuffix(strings.ToLower(curAbs), disabledJarSuffix) {
			newPath = curAbs[:len(curAbs)-len(".disabled")]
		} else {
			return nil
		}
	} else {
		if strings.HasSuffix(strings.ToLower(curAbs), jarSuffix) {
			newPath = curAbs + ".disabled"
		} else {
			return nil
		}
	}

	// 改名目标也必须落在同一受管 mods 目录、且仍是受管 jar，防止借启用/禁用把文件
	// 挪出 mods 目录或挪成非受管文件（防御纵深：正常情况下仅后缀变化，父目录不变）。
	toAbs, ok := resolveManagedModPath(mcDir, newPath)
	if !ok || !sameManagedModDir(curAbs, toAbs) {
		recordSecurityEvent(auditCategoryPermission, auditSeverityWarn, auditActionRejected,
			"ToggleMod", "拒绝把 Mod 改名到受管 Mods 目录之外: "+newPath)
		return fmt.Errorf("非法的 Mod 目标路径")
	}

	if err := os.Rename(curAbs, toAbs); err != nil {
		return fmt.Errorf("重命名失败: %v", err)
	}

	return nil
}

// ImportMod 导入 Mod 文件
