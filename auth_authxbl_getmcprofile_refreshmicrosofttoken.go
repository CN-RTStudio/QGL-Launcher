package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

)

func (a *App) RefreshMicrosoftToken(id string) error {
	authData, err := a.GetMSAuthData(id)
	if err != nil {
		return fmt.Errorf("读取认证数据失败: %v", err)
	}

	if authData.RefreshToken == "" {
		return fmt.Errorf("无刷新令牌，请重新登录")
	}

	// 检查是否需要刷新
	if time.Now().Unix() < authData.MCExpiresAt-60 {
		return nil
	}

	// 用 refresh_token 获取新的 access_token
	data := url.Values{
		"client_id":     {oauthClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {authData.RefreshToken},
		"scope":         {oauthScope},
	}

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return fmt.Errorf("刷新令牌请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return err
	}

	if tokenResp.Error != "" {
		return fmt.Errorf("刷新令牌失败: %s", tokenResp.ErrorDescription)
	}

	// 重新走 Xbox → Minecraft 流程
	xblToken, _, err := a.authXBL(tokenResp.AccessToken)
	if err != nil {
		return err
	}

	xstsToken, xstsUHS, err := a.authXSTS(xblToken)
	if err != nil {
		return err
	}

	mcAccessToken, mcExpiresIn, err := a.authMinecraft(xstsToken, xstsUHS)
	if err != nil {
		return err
	}

	// 更新存储
	authData.AccessToken = tokenResp.AccessToken
	authData.RefreshToken = tokenResp.RefreshToken
	authData.MCAccessToken = mcAccessToken
	authData.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix()
	authData.MCExpiresAt = time.Now().Add(time.Duration(mcExpiresIn) * time.Second).Unix()

	return a.SaveMSAuthData(id, authData)
}

// GetMSAuthData 获取微软认证数据（自动处理加密/明文兼容；参数为用户标识 dir）
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
