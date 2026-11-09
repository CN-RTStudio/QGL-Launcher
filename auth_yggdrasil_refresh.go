package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (a *App) RefreshExternalToken(username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	authData, err := a.GetExternalAuthData(username)
	if err != nil {
		return fmt.Errorf("获取外置认证数据失败: %v", err)
	}
	refreshURL := authData.ServerURL + "/authserver/refresh"
	payload := map[string]interface{}{
		"accessToken": authData.AccessToken,
		"clientToken": authData.ClientToken,
		"requestUser": true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("构建请求失败: %v", err)
	}
	req, err := http.NewRequest("POST", refreshURL, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := yggHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("连接验证服务器失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := readAuthJSON(resp)
	if err != nil {
		return fmt.Errorf("读取响应失败: %v", err)
	}
	var authResp YggdrasilAuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}
	if authResp.Error != "" {
		if authData.Password != "" {
			newAuthData, loginErr := a.LoginYggdrasil(authData.ServerURL, authData.Username, authData.Password)
			if loginErr != nil {
				return fmt.Errorf("令牌刷新失败且重新登录失败: %v", loginErr)
			}
			newAuthData.ServerURL = authData.ServerURL
			newAuthData.ServerName = authData.ServerName
			return a.SaveExternalAuthData(username, newAuthData)
		}
		return fmt.Errorf("令牌刷新失败: %s", authResp.ErrorMessage)
	}
	if why := validateYggToken(authResp.AccessToken, false); why != ypOK {
		recordSecurityEvent("auth", "high", "reject-ygg-token", "RefreshExternalToken", why)
		return fmt.Errorf("%s", describeYggReject(why))
	}
	authData.AccessToken = authResp.AccessToken
	if why := validateYggToken(authResp.ClientToken, true); why == ypOK && authResp.ClientToken != "" {
		authData.ClientToken = authResp.ClientToken
	}
	// 刷新响应若带角色资料，同样必须通过名校验与 UUID 归一；非法则保留旧身份不覆盖。
	if profile, ok := pickYggProfile(authResp.SelectedProfile, authResp.AvailableProfiles); ok {
		authData.UUID = profile.UUID
		authData.Username = profile.Name
	} else if authResp.SelectedProfile != nil {
		recordSecurityEvent("auth", "medium", "ignore-ygg-profile", "RefreshExternalToken", "invalid refreshed profile")
	}
	return a.SaveExternalAuthData(username, authData)
}
