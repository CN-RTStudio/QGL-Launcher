package main

import (
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
