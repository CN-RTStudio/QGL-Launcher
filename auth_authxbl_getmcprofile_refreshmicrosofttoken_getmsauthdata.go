package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) GetMSAuthData(id string) (*MSAuthData, error) {
	authPath := filepath.Join(a.userDirFor(id), "ms_auth.json")
	data, err := os.ReadFile(authPath)
	if err != nil {
		return nil, err
	}
	// 加密密钥基于显示用户名（迁移重命名文件夹后仍可解密）
	displayName := a.userNameByID(id)

	// 先尝试按加密格式解析
	var encData MSAuthDataEncrypted
	if err := json.Unmarshal(data, &encData); err == nil && encData.Data != "" {
		// 加密格式：解密 Data 字段
		key := getEncryptionKey(displayName)
		decrypted, err := aesGCMDecrypt(encData.Data, key)
		if err != nil {
			return nil, fmt.Errorf("解密认证数据失败: %w", err)
		}
		var authData MSAuthData
		if err := json.Unmarshal(decrypted, &authData); err != nil {
			return nil, fmt.Errorf("解析解密后的认证数据失败: %w", err)
		}
		if authData.Username == "" || encData.Username != "" {
			authData.Username = displayName // 确保用户名正确
		}
		return &authData, nil
	}

	// 兼容旧版明文格式
	var authData MSAuthData
	if err := json.Unmarshal(data, &authData); err != nil {
		return nil, err
	}
	return &authData, nil
}

// SaveMSAuthData 保存微软认证数据（加密存储，username 以外的字段全部加密；参数为用户标识 dir）
