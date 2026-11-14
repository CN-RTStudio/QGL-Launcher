package main

import (
	"fmt"

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
