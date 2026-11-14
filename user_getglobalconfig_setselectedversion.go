package main

import (
	"fmt"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) SetSelectedVersion(versionID string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		config = &UserConfig{}
	}
	config.SelectedVersion = versionID
	return a.SaveUserConfig(currentUser.Dir, config)
}

// GetThemeColor 获取当前用户的主题色
func (a *App) GetThemeColor() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return "cyan"
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil || config.ThemeColor == "" {
		return "cyan"
	}
	return config.ThemeColor
}

// GetUserOOBEDone 当前用户的用户向导是否已完成
func (a *App) GetUserOOBEDone() (bool, error) {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false, err
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		return false, err
	}
	return config.OOBE, nil
}

// SetUserOOBEDone 标记当前用户的用户向导已完成
func (a *App) SetUserOOBEDone() error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return err
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		config = &UserConfig{}
	}
	config.OOBE = true
	return a.SaveUserConfig(currentUser.Dir, config)
}

// SetThemeColor 设置当前用户的主题色
func (a *App) SetThemeColor(color string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		config = &UserConfig{}
	}
	config.ThemeColor = color
	err = a.SaveUserConfig(currentUser.Dir, config)
	if err != nil {
		return err
	}
	runtime.EventsEmit(a.ctx, "themeChanged", color)
	return nil
}

// GetShowExportLaunchCommand 获取是否显示导出启动命令按钮
func (a *App) GetShowExportLaunchCommand() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	config, err := a.GetUserConfig(currentUser.Dir)
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
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		config = &UserConfig{}
	}
	config.ShowExportLaunchCommand = show
	return a.SaveUserConfig(currentUser.Dir, config)
}

// GetBackgroundImage 获取当前用户的背景图片路径
