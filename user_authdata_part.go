package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func (a *App) LoginUser(username string, password string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	userType := a.GetUserType(username)
	if userType == UserTypeGuest {
		// 访客用户：不需要密码即可进入，但进入后处于锁定状态
		a.guestUnlocked = false
		return a.SetCurrentUser(username)
	}
	if userType == UserTypePremium {
		// 正版用户：刷新令牌，如果刷新失败则需要重新登录
		if err := a.RefreshMicrosoftToken(username); err != nil {
			return fmt.Errorf("正版令牌已过期，请重新登录: %v", err)
		}
		return a.SetCurrentUser(username)
	}
	if userType == UserTypeExternal {
		// 外置用户：刷新令牌
		if err := a.RefreshExternalToken(username); err != nil {
			return fmt.Errorf("外置登录令牌已过期，请重新登录: %v", err)
		}
		return a.SetCurrentUser(username)
	}
	// 离线用户：正常密码验证
	hasPwd, err := a.UserHasPassword(username)
	if err != nil {
		return fmt.Errorf("检查用户密码失败: %w", err)
	}
	if hasPwd {
		if password == "" {
			return fmt.Errorf("该用户已设置密码，请输入密码")
		}
		userDir := filepath.Join(a.GetUsersDir(), username)
		pwdPath := filepath.Join(userDir, "password.json")
		pwdData, err := readPasswordData(pwdPath)
		if err != nil {
			return fmt.Errorf("读取密码文件失败: %w", err)
		}
		// 安全加固: 使用 bcrypt 验证密码
		if !verifyPassword(password, pwdData.PasswordHash) {
			return fmt.Errorf("密码错误")
		}
	} else {
		if password != "" {
			return fmt.Errorf("该用户未设置密码，无需输入密码")
		}
	}
	return a.SetCurrentUser(username)
}

// UnlockGuest 解锁访客用户（输入安全密码）
func (a *App) UnlockGuest(securityPassword string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	if currentUser.Type != UserTypeGuest {
		return fmt.Errorf("当前用户不是访客用户")
	}
	if securityPassword == "" {
		return fmt.Errorf("请输入安全密码")
	}
	userDir := filepath.Join(a.GetUsersDir(), currentUser.Username)
	pwdPath := filepath.Join(userDir, "password.json")
	pwdData, err := readPasswordData(pwdPath)
	if err != nil {
		return fmt.Errorf("读取安全密码文件失败: %w", err)
	}
	// 安全加固: 使用 bcrypt 验证密码
	if !verifyPassword(securityPassword, pwdData.PasswordHash) {
		return fmt.Errorf("安全密码错误")
	}
	a.guestUnlocked = true
	return nil
}

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
