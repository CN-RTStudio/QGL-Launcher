package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) SaveMSAuthData(id string, authData *MSAuthData) error {
	userDir := a.userDirFor(id)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return err
	}
	displayName := a.userNameByID(id)

	// 构建需要加密的数据（除 username 以外的所有字段）
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

	// 加密（密钥基于显示用户名）
	key := getEncryptionKey(displayName)
	encrypted, err := aesGCMEncrypt(payloadBytes, key)
	if err != nil {
		return fmt.Errorf("加密认证数据失败: %w", err)
	}

	// 构建加密后的存储格式
	encData := MSAuthDataEncrypted{
		Username: displayName,
		Data:     encrypted,
	}

	data, err := json.MarshalIndent(encData, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(userDir, "ms_auth.json"), data, 0644)
}

// ===== Yggdrasil 外置登录 =====

// YggdrasilAuthResponse Yggdrasil 认证响应
type YggdrasilAuthResponse struct {
	AccessToken      string `json:"accessToken"`
	ClientToken      string `json:"clientToken"`
	AvailableProfiles []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"availableProfiles"`
	SelectedProfile *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"selectedProfile"`
	Error            string `json:"error"`
	ErrorMessage     string `json:"errorMessage"`
	Cause            string `json:"cause"`
}

// YggdrasilServerMeta Yggdrasil 服务器元信息
type YggdrasilServerMeta struct {
	ServerName string `json:"serverName"`
}

// YggdrasilServerLinks Yggdrasil 服务器链接
type YggdrasilServerLinks struct {
	Homepage string `json:"homepage"`
	Register string `json:"register"`
}

// YggdrasilServerInfo Yggdrasil 服务器信息
type YggdrasilServerInfo struct {
	Meta  YggdrasilServerMeta  `json:"meta"`
	Links YggdrasilServerLinks `json:"links"`
}

// normalizeYggdrasilURL 规范化 Yggdrasil 服务器地址
