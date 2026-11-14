package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

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
