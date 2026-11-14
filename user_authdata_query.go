package main

import (
	"fmt"
)

func (a *App) GetCurrentUser() (UserInfo, error) {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return UserInfo{}, fmt.Errorf("读取全局配置失败: %w", err)
	}
	if config.CurrentUser == "" {
		return UserInfo{}, fmt.Errorf("未设置当前用户")
	}
	if err := validateUsername(config.CurrentUser); err != nil {
		return UserInfo{}, fmt.Errorf("无效的用户名")
	}
	hasPwd, err := a.UserHasPassword(config.CurrentUser)
	if err != nil {
		hasPwd = false
	}
	userType := a.GetUserType(config.CurrentUser)
	isLocked := false
	if userType == UserTypeGuest {
		isLocked = !a.guestUnlocked
	}
	return UserInfo{
		Username:    config.CurrentUser,
		HasPassword: hasPwd,
		Type:        userType,
		IsLocked:    isLocked,
	}, nil
}
