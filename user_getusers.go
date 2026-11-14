package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) GetUsers() ([]UserInfo, error) {
	entries := a.loadUserRegistry()

	var users []UserInfo
	for _, entry := range entries {
		hasPwd, err := a.UserHasPassword(entry.Dir)
		if err != nil {
			hasPwd = false
		}
		userType := entry.Type
		isLocked := false
		if userType == UserTypeGuest {
			isLocked = !a.guestUnlocked
		}
		serverName := ""
		serverURL := ""
		if userType == UserTypeExternal {
			extData, extErr := a.GetExternalAuthData(entry.Dir)
			if extErr == nil {
				serverName = extData.ServerName
				serverURL = extData.ServerURL
			}
		}
		users = append(users, UserInfo{
			Username:    entry.Name,
			Dir:         entry.Dir,
			HasPassword: hasPwd,
			Type:        userType,
			IsLocked:    isLocked,
			ServerName:  serverName,
			ServerURL:   serverURL,
		})
	}
	return users, nil
}

// CreateGuestUser 创建访客用户（需要安全密码），返回用户标识 dir
func (a *App) CreateGuestUser(username string, securityPassword string) (string, error) {
	if securityPassword == "" {
		return "", fmt.Errorf("访客用户必须设置安全密码")
	}
	dir, err := a.CreateUser(username, "")
	if err != nil {
		return "", err
	}
	// 访客用户的密码文件存储安全密码
	userDir := a.userDirFor(dir)
	hash := md5.Sum([]byte(securityPassword))
	pwdData := PasswordData{
		PasswordMD5: fmt.Sprintf("%x", hash),
	}
	pwdBytes, err := json.MarshalIndent(pwdData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化密码数据失败: %w", err)
	}
	pwdPath := filepath.Join(userDir, "password.json")
	if err := os.WriteFile(pwdPath, pwdBytes, 0644); err != nil {
		return "", fmt.Errorf("写入密码文件失败: %w", err)
	}
	// 保存用户类型为访客
	return dir, a.saveUserType(dir, UserTypeGuest)
}

// CreateOfflineUser 创建离线用户（可选密码），返回用户标识 dir
