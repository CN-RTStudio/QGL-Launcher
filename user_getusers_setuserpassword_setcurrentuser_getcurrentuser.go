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
	// CurrentUser 为用户标识（随机文件夹名），从注册表解析显示用户名
	entry := a.findUserEntry(config.CurrentUser)
	displayName := config.CurrentUser
	if entry != nil {
		displayName = entry.Name
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
		Username:    displayName,
		Dir:         config.CurrentUser,
		HasPassword: hasPwd,
		Type:        userType,
		IsLocked:    isLocked,
	}, nil
}
