package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

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
