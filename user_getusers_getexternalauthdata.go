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
