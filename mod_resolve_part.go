package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
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
func (a *App) ImportMod(versionID string) error {
	if versionID != "" {
		if strings.Contains(versionID, "..") || strings.Contains(versionID, "/") || strings.Contains(versionID, "\\") {
			return fmt.Errorf("版本ID包含非法字符")
		}
	}
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

	// 纵深防御：无论是否版本隔离，导入落点都必须解析在 .minecraft 内，
	// 防止 versionID / 配置异常把 jar 写到游戏目录之外。
	if _, ok := PathWithin(mcDir, modsDir); !ok {
		return fmt.Errorf("Mods 目录越界，拒绝导入: %s", modsDir)
	}
	// 0700 建目录；目录已存在但权限偏宽时也一并收权（MkdirAll 不会收权）。
	if err := ensurePrivateDir(modsDir); err != nil {
		return fmt.Errorf("创建 Mod 目录失败: %w", err)
	}

	// 用户手动导入的 jar 完全没有下载链的哈希 / 主机白名单背书，更要在落进
	// mods 目录前做静态扫描，挡掉本地双击“安装”的恶意 jar（critical 阻断）。
	if _, err := enforceModJarScan(path, "mod-import", filepath.Base(path)); err != nil {
		return fmt.Errorf("Mod 安全扫描失败: %w", err)
	}

	// 手动导入的文件名同样走 nameguard（挡控制字符 / 保留设备名 / 尾点等），
	// 且只接受 .jar（.zip / .jar.disabled 不允许经“导入 Mod”入口进入 mods 目录）。
	fileName, whyName := SafeModFileName(filepath.Base(path))
	if whyName != nameRejectNone || !strings.HasSuffix(strings.ToLower(fileName), ".jar") {
		return fmt.Errorf("Mod 文件名无效: %s", describeNameReject(whyName))
	}
	// 与下载链一致：目录里已有大小写 / 尾点等价同名文件时改名避让，避免覆盖或
	// 与既有 Mod 在大小写不敏感卷上撞成同一文件。
	plannedName, collided, planErr := planModDestName(modsDir, fileName)
	if planErr != nil {
		return planErr
	}
	if collided {
		recordSecurityEvent("download", auditSeverityWarn, auditActionDetected,
			"mod-name-collision", "导入时发现同名 Mod，已改名避让: "+fileName+" -> "+plannedName)
	}
	fileName = plannedName
	destPath := filepath.Join(modsDir, fileName)

	// 统一走安全复制内核，替换旧的 os.Open + io.Copy + OpenFile(O_TRUNC)：
	// 源拒绝符号链接 / 特殊文件；LimitReader+1 有界复制（上限沿用下载链
	// maxDownloadBytes，stat 之后文件继续增长也会在多读 1 字节时被拦下，堵 TOCTOU）；
	// 目标写 0600 临时文件 + fsync + 原子 rename，杜绝跟随预置符号链接写穿与半截文件。
	if err := copyFileSecure(path, destPath, privateFilePerm, maxDownloadBytes); err != nil {
		return fmt.Errorf("复制 Mod 文件失败: %w", err)
	}

	return nil
}

// DeleteMod 删除 Mod 文件
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

// downloadModItem 下载 Mod 文件
