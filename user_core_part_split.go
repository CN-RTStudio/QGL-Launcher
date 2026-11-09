package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func (a *App) GetUsers() ([]UserInfo, error) {
	usersDir := a.GetUsersDir()
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil, fmt.Errorf("读取用户目录失败: %w", err)
	}
	var users []UserInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		username := entry.Name()
		if err := validateUsername(username); err != nil {
			continue
		}
		hasPwd, err := a.UserHasPassword(username)
		if err != nil {
			hasPwd = false
		}
		userType := a.GetUserType(username)
		isLocked := false
		if userType == UserTypeGuest {
			isLocked = !a.guestUnlocked
		}
		serverName := ""
		if userType == UserTypeExternal {
			extData, extErr := a.GetExternalAuthData(username)
			if extErr == nil {
				serverName = extData.ServerName
			}
		}
		users = append(users, UserInfo{
			Username:    username,
			HasPassword: hasPwd,
			Type:        userType,
			IsLocked:    isLocked,
			ServerName:  serverName,
		})
	}
	return users, nil
}

// CreateGuestUser 创建访客用户（需要安全密码）
func (a *App) CreateGuestUser(username string, securityPassword string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if securityPassword == "" {
		return fmt.Errorf("访客用户必须设置安全密码")
	}
	if err := a.CreateUser(username, ""); err != nil {
		return err
	}
	// 访客用户的密码文件存储安全密码
	userDir := filepath.Join(a.GetUsersDir(), username)
	// 安全加固: 使用 bcrypt 哈希密码
	hash, err := hashPassword(securityPassword)
	if err != nil {
		return fmt.Errorf("密码哈希失败: %w", err)
	}
	pwdData := PasswordData{
		PasswordHash: hash,
	}
	pwdBytes, err := json.MarshalIndent(pwdData, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化密码数据失败: %w", err)
	}
	pwdPath := filepath.Join(userDir, "password.json")
	// 安全加固: 密码文件权限 0600，且原子写 / 拒绝符号链接写穿
	if err := secureWritePrivateFile(pwdPath, pwdBytes); err != nil {
		return fmt.Errorf("写入密码文件失败: %w", err)
	}
	// 保存用户类型为访客
	return a.saveUserType(username, UserTypeGuest)
}

// CreateOfflineUser 创建离线用户（可选密码）
func (a *App) CreateOfflineUser(username string, password string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if err := a.CreateUser(username, password); err != nil {
		return err
	}
	return a.saveUserType(username, UserTypeOffline)
}

// CreatePremiumUser 创建正版用户
func (a *App) CreatePremiumUser(username string, authData MSAuthData) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	// 创建用户目录和基础配置（不设置密码）
	if err := a.CreateUser(username, ""); err != nil {
		return err
	}
	// 保存用户类型为正版
	if err := a.saveUserType(username, UserTypePremium); err != nil {
		return err
	}
	// 保存微软认证数据
	return a.SaveMSAuthData(username, &authData)
}

// CreateExternalUser 创建外置用户
func (a *App) CreateExternalUser(username string, authData ExternalAuthData) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if err := a.CreateUser(username, ""); err != nil {
		return err
	}
	if err := a.saveUserType(username, UserTypeExternal); err != nil {
		return err
	}
	return a.SaveExternalAuthData(username, &authData)
}
