package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) LoginUser(id string, password string) error {
	userType := a.GetUserType(id)

	if userType == UserTypeGuest {
		// 访客用户：不需要密码即可进入，但进入后处于锁定状态
		a.guestUnlocked = false
		return a.SetCurrentUser(id)
	}

	if userType == UserTypePremium {
		// 正版用户：刷新令牌，如果刷新失败则需要重新登录
		if err := a.RefreshMicrosoftToken(id); err != nil {
			return fmt.Errorf("正版令牌已过期，请重新登录: %v", err)
		}
		return a.SetCurrentUser(id)
	}

	if userType == UserTypeExternal {
		// 外置用户：刷新令牌
		if err := a.RefreshExternalToken(id); err != nil {
			return fmt.Errorf("外置登录令牌已过期，请重新登录: %v", err)
		}
		return a.SetCurrentUser(id)
	}

	// 离线用户：正常密码验证
	hasPwd, err := a.UserHasPassword(id)
	if err != nil {
		return fmt.Errorf("检查用户密码失败: %w", err)
	}

	if hasPwd {
		if password == "" {
			return fmt.Errorf("该用户已设置密码，请输入密码")
		}
		pwdPath := filepath.Join(a.userDirFor(id), "password.json")
		pwdBytes, err := os.ReadFile(pwdPath)
		if err != nil {
			return fmt.Errorf("读取密码文件失败: %w", err)
		}
		var pwdData PasswordData
		if err := json.Unmarshal(pwdBytes, &pwdData); err != nil {
			return fmt.Errorf("解析密码文件失败: %w", err)
		}
		hash := md5.Sum([]byte(password))
		inputMD5 := fmt.Sprintf("%x", hash)
		if inputMD5 != pwdData.PasswordMD5 {
			return fmt.Errorf("密码错误")
		}
	} else {
		if password != "" {
			return fmt.Errorf("该用户未设置密码，无需输入密码")
		}
	}

	return a.SetCurrentUser(id)
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

	userDir := a.userDirFor(currentUser.Dir)
	pwdPath := filepath.Join(userDir, "password.json")
	pwdBytes, err := os.ReadFile(pwdPath)
	if err != nil {
		return fmt.Errorf("读取安全密码文件失败: %w", err)
	}
	var pwdData PasswordData
	if err := json.Unmarshal(pwdBytes, &pwdData); err != nil {
		return fmt.Errorf("解析安全密码文件失败: %w", err)
	}
	hash := md5.Sum([]byte(securityPassword))
	inputMD5 := fmt.Sprintf("%x", hash)
	if inputMD5 != pwdData.PasswordMD5 {
		return fmt.Errorf("安全密码错误")
	}

	a.guestUnlocked = true
	return nil
}

// IsGuestLocked 检查当前访客用户是否锁定
