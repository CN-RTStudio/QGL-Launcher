package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

func (a *App) RefreshMicrosoftToken(username string) error {
	if !authRateLimiter.Allow("ms-refresh-" + username) {
		return fmt.Errorf("刷新令牌过于频繁，请稍后再试")
	}
	if err := validateUsername(username); err != nil {
		return err
	}
	authData, err := a.GetMSAuthData(username)
	if err != nil {
		return fmt.Errorf("读取认证数据失败: %v", err)
	}
	if authData.RefreshToken == "" {
		return fmt.Errorf("无刷新令牌，请重新登录")
	}
	if time.Now().Unix() < authData.MCExpiresAt-60 {
		return nil
	}
	data := url.Values{
		"client_id":     {oauthClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {authData.RefreshToken},
		"scope":         {oauthScope},
	}
	resp, err := httpClient.PostForm(tokenURL, data)
	if err != nil {
		return fmt.Errorf("刷新令牌请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, err := readAuthJSON(resp)
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
	now := time.Now()
	authData.AccessToken = tokenResp.AccessToken
	// 微软刷新响应可能不重复下发 refresh_token（令牌轮转但本响应缺字段）；
	// 此时绝不能用空串覆盖掉旧的 refresh_token，否则下一次刷新会直接废掉。
	if tokenResp.RefreshToken != "" {
		authData.RefreshToken = tokenResp.RefreshToken
	}
	authData.MCAccessToken = mcAccessToken
	authData.ExpiresAt = tokenExpiryUnix(now, tokenResp.ExpiresIn)
	authData.MCExpiresAt = tokenExpiryUnix(now, mcExpiresIn)
	return a.SaveMSAuthData(username, authData)
}
