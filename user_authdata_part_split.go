package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// IsGuestLocked 检查当前访客用户是否锁定
func (a *App) IsGuestLocked() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	if currentUser.Type != UserTypeGuest {
		return false
	}
	return !a.guestUnlocked
}

// LockGuest 重新锁定访客用户
func (a *App) LockGuest() {
	a.guestUnlocked = false
}

func (a *App) SetCurrentUser(username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}
	config.CurrentUser = username
	return a.SaveGlobalConfig(config)
}

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

func (a *App) UserHasPassword(username string) (bool, error) {
	if err := validateUsername(username); err != nil {
		return false, err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	pwdPath := filepath.Join(userDir, "password.json")
	pwdData, err := readPasswordData(pwdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		// 体积超限 / 符号链接 / 解析损坏一律 fail-closed 阻断登录，绝不能把一个
		// 被异常改写的密码文件当成“未设密码”，否则本地预置畸形文件即可绕过口令。
		return false, fmt.Errorf("读取密码文件失败: %w", err)
	}
	return pwdData.PasswordHash != "", nil
}
