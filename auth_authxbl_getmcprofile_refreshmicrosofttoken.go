package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
