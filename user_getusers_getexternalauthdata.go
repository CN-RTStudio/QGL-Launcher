package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) GetExternalAuthData(id string) (*ExternalAuthData, error) {
	userDir := a.userDirFor(id)
	data, err := os.ReadFile(filepath.Join(userDir, "external_auth.json"))
	if err != nil {
		return nil, fmt.Errorf("读取外置认证数据失败: %w", err)
	}

	// 先尝试按加密格式解析
	var encData ExternalAuthDataEncrypted
	if err := json.Unmarshal(data, &encData); err == nil && encData.Data != "" {
		// 加密格式：解密 Data 字段（密钥基于显示用户名）
		key := getEncryptionKey(a.userNameByID(id))
		decrypted, err := aesGCMDecrypt(encData.Data, key)
		if err != nil {
			return nil, fmt.Errorf("解密外置认证数据失败: %w", err)
		}
		var authData ExternalAuthData
		if err := json.Unmarshal(decrypted, &authData); err != nil {
			return nil, fmt.Errorf("解析解密后的外置认证数据失败: %w", err)
		}
		authData.ServerName = encData.ServerName // 服务器名称不加密
		return &authData, nil
	}

	// 兼容旧版明文格式
	var authData ExternalAuthData
	if err := json.Unmarshal(data, &authData); err != nil {
		return nil, fmt.Errorf("解析外置认证数据失败: %w", err)
	}
	return &authData, nil
}

// CreateUser 创建用户基础方法：文件夹名使用随机字符串，注册进 user.json，返回用户标识 dir
func (a *App) CreateUser(username string, password string) (string, error) {
	dir := randomDirName()
	userDir := a.userDirFor(dir)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return "", fmt.Errorf("创建用户目录失败: %w", err)
	}

	// 注册进用户注册表（显示名可重复，dir 唯一）
	entries := a.loadUserRegistry()
	entries = append(entries, UserEntry{Name: username, Type: UserTypeOffline, Dir: dir})
	if err := a.saveUserRegistry(entries); err != nil {
		return "", fmt.Errorf("写入用户注册表失败: %w", err)
	}

	if password != "" {
		hash := md5.Sum([]byte(password))
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
	}

	defaultConfig := UserConfig{
		VersionIsolation: false,
		SelectedVersion:  "",
	}
	configBytes, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化用户配置失败: %w", err)
	}
	configPath := filepath.Join(userDir, "config.json")
	if err := os.WriteFile(configPath, configBytes, 0644); err != nil {
		return "", fmt.Errorf("写入用户配置文件失败: %w", err)
	}

	return dir, nil
}

// LoginUser 登录用户（参数为用户标识 dir）
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

// ===== 用户管理（管理当前用户）=====

// getUserPasswordMD5 读取用户密码 MD5（无密码返回 ""；参数为用户标识 dir）
func (a *App) getUserPasswordMD5(id string) string {
	pwdPath := filepath.Join(a.userDirFor(id), "password.json")
	pwdBytes, err := os.ReadFile(pwdPath)
	if err != nil {
		return ""
	}
	var pwdData PasswordData
	if json.Unmarshal(pwdBytes, &pwdData) != nil {
		return ""
	}
	return pwdData.PasswordMD5
}

// SetUserPassword 设置/修改当前用户的密码
// 有原密码时必须先验证原密码；newPassword 为空则清除密码
