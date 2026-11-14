package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (a *App) GetYggdrasilServerInfo(serverURL string) (*YggdrasilServerInfo, error) {
	normalized, err := normalizeYggdrasilURL(serverURL)
	if err != nil {
		return nil, err
	}
	serverURL = normalized
	infoURL := strings.TrimSuffix(serverURL, "/api/yggdrasil")
	if !strings.HasSuffix(infoURL, "/") {
		infoURL += "/"
	}
	resp, err := yggHTTPClient.Get(infoURL)
	if err != nil {
		return nil, fmt.Errorf("无法连接到验证服务器: %v", err)
	}
	defer resp.Body.Close()
	body, err := readAuthJSON(resp)
	if err != nil {
		return nil, fmt.Errorf("读取服务器信息失败: %v", err)
	}
	var info YggdrasilServerInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("解析服务器信息失败: %v", err)
	}
	return &info, nil
}

// LoginYggdrasil Yggdrasil 外置登录
func (a *App) LoginYggdrasil(serverURL string, username string, password string) (*ExternalAuthData, error) {
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if !authRateLimiter.Allow("ygg-" + username) {
		return nil, fmt.Errorf("登录请求过于频繁，请稍后再试")
	}
	normalized, err := normalizeYggdrasilURL(serverURL)
	if err != nil {
		return nil, err
	}
	serverURL = normalized
	authURL := serverURL + "/authserver/authenticate"
	payload := map[string]interface{}{
		"agent": map[string]interface{}{
			"name":    "Minecraft",
			"version": 1,
		},
		"username":    username,
		"password":    password,
		"requestUser": true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("构建请求失败: %v", err)
	}
	req, err := http.NewRequest("POST", authURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := yggHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接验证服务器失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := readAuthJSON(resp)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}
	var authResp YggdrasilAuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}
	if authResp.Error != "" {
		errMsg := authResp.ErrorMessage
		if errMsg == "" {
			errMsg = authResp.Error
		}
		if authResp.Error == "ForbiddenOperationException" {
			return nil, fmt.Errorf("用户名或密码错误")
		}
		return nil, fmt.Errorf("登录失败: %s", errMsg)
	}
	if authResp.AccessToken == "" {
		return nil, fmt.Errorf("登录失败: 未获取到访问令牌")
	}
	// 令牌来自不可信外置服务器：限长且禁控制字符 / 空白（防存储膨胀与潜在头注入）。
	if why := validateYggToken(authResp.AccessToken, false); why != ypOK {
		recordSecurityEvent("auth", "high", "reject-ygg-token", "LoginYggdrasil", why)
		return nil, fmt.Errorf("%s", describeYggReject(why))
	}
	if why := validateYggToken(authResp.ClientToken, true); why != ypOK {
		recordSecurityEvent("auth", "high", "reject-ygg-client-token", "LoginYggdrasil", why)
		authResp.ClientToken = ""
	}
	// 角色名 / UUID 会落盘成账号文件并进入启动命令行，必须按 Minecraft 字符集与
	// 32 位 hex 校验，拒绝恶意服务器返回的穿越名 / 注入名 / 畸形 UUID。
	profile, ok := pickYggProfile(authResp.SelectedProfile, authResp.AvailableProfiles)
	if !ok {
		recordSecurityEvent("auth", "high", "reject-ygg-profile", "LoginYggdrasil", "no valid profile")
		return nil, fmt.Errorf("外置服务器返回的角色资料不合法，拒绝登录")
	}
	serverName := ""
	serverInfo, infoErr := a.GetYggdrasilServerInfo(serverURL)
	if infoErr == nil {
		if safe, ok := validateYggServerName(serverInfo.Meta.ServerName); ok && safe != "" {
			serverName = safe
		}
	}
	return &ExternalAuthData{
		ServerURL:   serverURL,
		AccessToken: authResp.AccessToken,
		ClientToken: authResp.ClientToken,
		UUID:        profile.UUID,
		Username:    profile.Name,
		Password:    password,
		ServerName:  serverName,
	}, nil
}

// RefreshExternalToken 刷新外置登录令牌
