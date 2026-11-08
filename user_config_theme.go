package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) SetThemeColor(color string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	// 主题色会被前端读回用于 data-theme / 样式键，落盘前强制白名单，
	// 拒绝未知值与夹带控制字符 / 标记的配置投毒。
	safeColor, reason := SafeThemeColor(color)
	if reason != configRejectNone {
		recordSecurityEvent(auditCategoryConfig, auditSeverityWarn, auditActionRejected,
			"SetThemeColor", "拒绝非法主题色: "+reason)
		return fmt.Errorf("无效的主题色: %s", reason)
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.ThemeColor = safeColor
	err = a.SaveUserConfig(currentUser.Username, config)
	if err != nil {
		return err
	}
	runtime.EventsEmit(a.ctx, "themeChanged", safeColor)
	return nil
}

// GetShowExportLaunchCommand 获取是否显示导出启动命令按钮
func (a *App) GetShowExportLaunchCommand() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return false
	}
	return config.ShowExportLaunchCommand
}

// SetShowExportLaunchCommand 设置是否显示导出启动命令按钮
func (a *App) SetShowExportLaunchCommand(show bool) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.ShowExportLaunchCommand = show
	return a.SaveUserConfig(currentUser.Username, config)
}

// GetBackgroundImage 获取当前用户的背景图片路径
func (a *App) GetBackgroundImage() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return ""
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return ""
	}
	return config.BackgroundImage
}

// allowedBackgroundRoots 列出允许作为背景图来源的根目录。
func (a *App) allowedBackgroundRoots() []string {
	roots := []string{filepath.Join(a.GetQGLDir(), "cache")}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots,
			filepath.Join(home, "Pictures"),
			filepath.Join(home, "Videos"),
		)
	}
	return roots
}

// isSafeBackgroundPath 校验背景图片路径：
//  1. 文件必须存在且是普通文件；
//  2. 扩展名必须是图片类型（走 sanitize.go 的白名单）；
//  3. 路径不能是符号链接；
//  4. 路径必须落在 QGL/cache 或用户 Pictures/Videos 目录下。
func (a *App) isSafeBackgroundPath(p string) bool {
	if p == "" || IsSymlink(p) {
		return false
	}
	info, err := os.Stat(p)
	if err != nil || info.IsDir() || info.Size() > maxBackgroundImageBytes {
		return false
	}
	if !IsSafeImageExt(p) {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	for _, root := range a.allowedBackgroundRoots() {
		if _, ok := PathWithin(root, abs); ok {
			return true
		}
	}
	return false
}
