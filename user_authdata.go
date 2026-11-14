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
