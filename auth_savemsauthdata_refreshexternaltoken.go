package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

)

func (a *App) RefreshExternalToken(id string) error {
	authData, err := a.GetExternalAuthData(id)
	if err != nil {
		return fmt.Errorf("获取外置认证数据失败: %v", err)
	}

	// 尝试 refresh 端点
	refreshURL := authData.ServerURL + "/authserver/refresh"

	payload := map[string]interface{}{
		"accessToken":  authData.AccessToken,
		"clientToken":  authData.ClientToken,
		"requestUser":  true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("构建请求失败: %v", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("POST", refreshURL, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("连接验证服务器失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %v", err)
	}

	var authResp YggdrasilAuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}

	if authResp.Error != "" {
		// refresh 失败，尝试用密码重新登录
		if authData.Password != "" {
			newAuthData, loginErr := a.LoginYggdrasil(authData.ServerURL, authData.Username, authData.Password)
			if loginErr != nil {
				return fmt.Errorf("令牌刷新失败且重新登录失败: %v", loginErr)
			}
			newAuthData.ServerURL = authData.ServerURL
			newAuthData.ServerName = authData.ServerName
			return a.SaveExternalAuthData(id, newAuthData)
		}
		return fmt.Errorf("令牌刷新失败: %s", authResp.ErrorMessage)
	}

	// 更新令牌
	authData.AccessToken = authResp.AccessToken
	if authResp.ClientToken != "" {
		authData.ClientToken = authResp.ClientToken
	}
	if authResp.SelectedProfile != nil {
		authData.UUID = authResp.SelectedProfile.ID
		authData.Username = authResp.SelectedProfile.Name
	}

	return a.SaveExternalAuthData(id, authData)
}

// DownloadAuthlibInjector 下载 authlib-injector.jar
