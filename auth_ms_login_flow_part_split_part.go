package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// GetMSAuthData 获取微软认证数据（自动处理加密/明文兼容）
func (a *App) GetMSAuthData(username string) (*MSAuthData, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	authPath := filepath.Join(a.GetUsersDir(), username, "ms_auth.json")
	// 凭据文件走有界读取（默认 64MiB 本地文本上限）并拒绝符号链接，防止超大 / 预置链接读入。
	data, err := readBoundedFile(authPath, localTextConfigMaxBytes)
	if err != nil {
		return nil, err
	}
	var encData MSAuthDataEncrypted
	if err := json.Unmarshal(data, &encData); err == nil && encData.Data != "" {
		saltPath := filepath.Join(a.GetUsersDir(), username, "ms_auth.salt")
		salt, _, _ := loadOrCreateAuthSalt(saltPath, false)
		key := getEncryptionKey(username, salt)
		decrypted, err := aesGCMDecrypt(encData.Data, key)
		if err != nil {
			return nil, fmt.Errorf("解密认证数据失败: %w", err)
		}
		var authData MSAuthData
		if err := json.Unmarshal(decrypted, &authData); err != nil {
			return nil, fmt.Errorf("解析解密后的认证数据失败: %w", err)
		}
		authData.Username = username
		return &authData, nil
	}
	var authData MSAuthData
	if err := json.Unmarshal(data, &authData); err != nil {
		return nil, fmt.Errorf("解析认证数据失败: %w", err)
	}
	return &authData, nil
}

// SaveMSAuthData 保存微软认证数据（加密存储，username 以外的字段全部加密）
func (a *App) SaveMSAuthData(username string, authData *MSAuthData) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return err
	}
	encryptPayload := map[string]interface{}{
		"accessToken":   authData.AccessToken,
		"refreshToken":  authData.RefreshToken,
		"mcAccessToken": authData.MCAccessToken,
		"uuid":          authData.UUID,
		"expiresAt":     authData.ExpiresAt,
		"mcExpiresAt":   authData.MCExpiresAt,
	}
	payloadBytes, err := json.Marshal(encryptPayload)
	if err != nil {
		return err
	}
	saltPath := filepath.Join(userDir, "ms_auth.salt")
	salt, _, _ := loadOrCreateAuthSalt(saltPath, true)
	key := getEncryptionKey(username, salt)
	encrypted, err := aesGCMEncrypt(payloadBytes, key)
	if err != nil {
		return fmt.Errorf("加密认证数据失败: %w", err)
	}
	encData := MSAuthDataEncrypted{
		Username: username,
		Data:     encrypted,
	}
	data, err := json.MarshalIndent(encData, "", "  ")
	if err != nil {
		return err
	}
	// 微软令牌是最高敏感级数据：原子写、0600、拒绝符号链接写穿
	return secureWritePrivateFile(filepath.Join(userDir, "ms_auth.json"), data)
}
