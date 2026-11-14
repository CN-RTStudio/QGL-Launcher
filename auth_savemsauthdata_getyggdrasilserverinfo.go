package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

)

func (a *App) GetYggdrasilServerInfo(serverURL string) (*YggdrasilServerInfo, error) {
	serverURL = normalizeYggdrasilURL(serverURL)
	// 请求服务器根路径获取信息
	infoURL := strings.TrimSuffix(serverURL, "/api/yggdrasil")
	if !strings.HasSuffix(infoURL, "/") {
		infoURL += "/"
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(infoURL)
	if err != nil {
		return nil, fmt.Errorf("无法连接到验证服务器: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
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
	serverURL = normalizeYggdrasilURL(serverURL)
	authURL := serverURL + "/authserver/authenticate"

	// 构建认证请求
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

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("POST", authURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接验证服务器失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	var authResp YggdrasilAuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	// 检查错误
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

	// 获取选中的角色
	var playerName string
	var playerUUID string
	if authResp.SelectedProfile != nil {
		playerName = authResp.SelectedProfile.Name
		playerUUID = authResp.SelectedProfile.ID
	} else if len(authResp.AvailableProfiles) > 0 {
		playerName = authResp.AvailableProfiles[0].Name
		playerUUID = authResp.AvailableProfiles[0].ID
	} else {
		return nil, fmt.Errorf("该账号还没有创建角色，请先在皮肤站创建角色")
	}

	// 获取服务器名称
	serverName := ""
	serverInfo, infoErr := a.GetYggdrasilServerInfo(serverURL)
	if infoErr == nil && serverInfo.Meta.ServerName != "" {
		serverName = serverInfo.Meta.ServerName
	}

	return &ExternalAuthData{
		ServerURL:   serverURL,
		AccessToken: authResp.AccessToken,
		ClientToken: authResp.ClientToken,
		UUID:        playerUUID,
		Username:    playerName,
		Password:    password,
		ServerName:  serverName,
	}, nil
}

// RefreshExternalToken 刷新外置登录令牌（参数为用户标识 dir）
