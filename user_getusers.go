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
func (a *App) CreateOfflineUser(username string, password string) (string, error) {
	dir, err := a.CreateUser(username, password)
	if err != nil {
		return "", err
	}
	return dir, a.saveUserType(dir, UserTypeOffline)
}

// CreatePremiumUser 创建正版用户，返回用户标识 dir
func (a *App) CreatePremiumUser(username string, authData MSAuthData) (string, error) {
	// 用户已存在（令牌过期重新登录）：只更新 ms_auth.json，不重置用户配置
	// 按 显示用户名+类型 在注册表中查找，同名不同类型的用户互不影响
	if entry := a.findUserByNameAndType(username, UserTypePremium); entry != nil {
		if err := a.SaveMSAuthData(entry.Dir, &authData); err != nil {
			return "", err
		}
		return entry.Dir, a.saveUserType(entry.Dir, UserTypePremium)
	}
	// 创建用户目录和基础配置（不设置密码）
	dir, err := a.CreateUser(username, "")
	if err != nil {
		return "", err
	}
	// 保存用户类型为正版
	if err := a.saveUserType(dir, UserTypePremium); err != nil {
		return "", err
	}
	// 保存微软认证数据
	return dir, a.SaveMSAuthData(dir, &authData)
}

// CreateExternalUser 创建外置用户，返回用户标识 dir
func (a *App) CreateExternalUser(username string, authData ExternalAuthData) (string, error) {
	// 按 显示用户名+类型 在注册表中查找（外置登录令牌过期重加场景）
	if entry := a.findUserByNameAndType(username, UserTypeExternal); entry != nil {
		if err := a.SaveExternalAuthData(entry.Dir, &authData); err != nil {
			return "", err
		}
		return entry.Dir, nil
	}
	dir, err := a.CreateUser(username, "")
	if err != nil {
		return "", err
	}
	if err := a.saveUserType(dir, UserTypeExternal); err != nil {
		return "", err
	}
	return dir, a.SaveExternalAuthData(dir, &authData)
}

// findUserByNameAndType 按显示用户名+类型查找注册表条目（同名不同类型不冲突）
func (a *App) findUserByNameAndType(name string, userType UserType) *UserEntry {
	entries := a.loadUserRegistry()
	for i := range entries {
		if entries[i].Name == name && entries[i].Type == userType {
			return &entries[i]
		}
	}
	return nil
}

// SaveExternalAuthData 保存外置登录认证数据（加密存储，和正版账号一样；参数为用户标识 dir）
func (a *App) SaveExternalAuthData(id string, authData *ExternalAuthData) error {
	userDir := a.userDirFor(id)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}

	// 构建需要加密的数据（除 serverName 以外的敏感字段）
	encryptPayload := map[string]interface{}{
		"serverUrl":   authData.ServerURL,
		"accessToken": authData.AccessToken,
		"clientToken": authData.ClientToken,
		"uuid":        authData.UUID,
		"username":    authData.Username,
		"password":    authData.Password,
	}
	payloadBytes, err := json.Marshal(encryptPayload)
	if err != nil {
		return fmt.Errorf("序列化外置认证数据失败: %w", err)
	}

	// 加密（密钥基于显示用户名，迁移重命名文件夹后仍可解密）
	key := getEncryptionKey(a.userNameByID(id))
	encrypted, err := aesGCMEncrypt(payloadBytes, key)
	if err != nil {
		return fmt.Errorf("加密外置认证数据失败: %w", err)
	}

	// 构建加密后的存储格式
	encData := ExternalAuthDataEncrypted{
		ServerName: authData.ServerName,
		Data:       encrypted,
	}

	data, err := json.MarshalIndent(encData, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化加密数据失败: %w", err)
	}
	return os.WriteFile(filepath.Join(userDir, "external_auth.json"), data, 0644)
}

// GetExternalAuthData 获取外置登录认证数据（解密读取；参数为用户标识 dir）
