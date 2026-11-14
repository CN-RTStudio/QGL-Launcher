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
