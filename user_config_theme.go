package main

import (
	"fmt"
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

func (a *App) SetBackgroundImage(path string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	// 安全加固：不接受任意路径，只能是 Pictures/Videos 或 QGL/cache 下的图片
	if !a.isSafeBackgroundPath(path) {
		return fmt.Errorf("背景图片路径不安全或不在允许目录内")
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.BackgroundImage = path
	err = a.SaveUserConfig(currentUser.Username, config)
	if err != nil {
		return err
	}
	runtime.EventsEmit(a.ctx, "backgroundChanged", path)
	return nil
}
