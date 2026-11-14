package main

import (
	"fmt"
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
