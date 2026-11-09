package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"os"
	"path/filepath"
	"strings"
)

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
