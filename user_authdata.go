package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func (a *App) SaveExternalAuthData(username string, authData *ExternalAuthData) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	if err := os.MkdirAll(userDir, 0700); err != nil {
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
	// 加密：外置认证数据与正版账号共用同一用户目录下的每用户随机盐 ms_auth.salt，
	// 保证同一用户不同凭据文件的密钥派生口径一致；盐缺失时生成，读不到则中止写入。
	saltPath := filepath.Join(userDir, "ms_auth.salt")
	salt, _, err := loadOrCreateAuthSalt(saltPath, true)
	if err != nil {
		return fmt.Errorf("准备认证盐失败: %w", err)
	}
	key := getEncryptionKey(username, salt)
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
	// 安全加固: 认证数据文件权限 0600，原子写并拒绝符号链接写穿
	return secureWritePrivateFile(filepath.Join(userDir, "external_auth.json"), data)
}

// GetExternalAuthData 获取外置登录认证数据（解密读取）
func (a *App) GetExternalAuthData(username string) (*ExternalAuthData, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	data, err := readPrivateStoreBytes(filepath.Join(userDir, "external_auth.json"), "外置认证数据")
	if err != nil {
		return nil, fmt.Errorf("读取外置认证数据失败: %w", err)
	}
	// 先尝试按加密格式解析
	var encData ExternalAuthDataEncrypted
	if err := json.Unmarshal(data, &encData); err == nil && encData.Data != "" {
		// 加密格式：解密 Data 字段。盐与写入侧一致；老数据没有盐文件时
		// loadOrCreateAuthSalt(create=false) 返回 nil，getEncryptionKey 回退旧硬编码盐。
		saltPath := filepath.Join(userDir, "ms_auth.salt")
		salt, _, _ := loadOrCreateAuthSalt(saltPath, false)
		key := getEncryptionKey(username, salt)
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

// CreateUser 创建用户基础方法
func (a *App) CreateUser(username string, password string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	if password != "" {
		// 安全加固: 使用 bcrypt 哈希密码
		hash, err := hashPassword(password)
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
		// 安全加固: 密码文件原子写、0600、拒绝符号链接写穿
		if err := secureWritePrivateFile(pwdPath, pwdBytes); err != nil {
			return fmt.Errorf("写入密码文件失败: %w", err)
		}
	}
	defaultConfig := UserConfig{
		VersionIsolation: false,
		SelectedVersion:  "",
	}
	configBytes, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化用户配置失败: %w", err)
	}
	configPath := filepath.Join(userDir, "config.json")
	if err := secureWritePrivateFile(configPath, configBytes); err != nil {
		return fmt.Errorf("写入用户配置文件失败: %w", err)
	}
	return nil
}
