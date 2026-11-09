package main

import (
	"encoding/json"
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"net/url"
)

func (a *App) StartMicrosoftLogin() (string, error) {
	if !authRateLimiter.Allow("ms-start") {
		return "", fmt.Errorf("登录请求过于频繁，请稍后再试")
	}
	data := url.Values{
		"client_id": {oauthClientID},
		"scope":     {oauthScope},
	}
	resp, err := httpClient.PostForm(deviceCodeURL, data)
	if err != nil {
		return "", fmt.Errorf("请求设备代码失败: %v", err)
	}
	defer resp.Body.Close()
	body, err := readAuthJSON(resp)
	if err != nil {
		return "", fmt.Errorf("读取设备代码响应失败: %v", err)
	}
	var dcResp DeviceCodeResponse
	if err := json.Unmarshal(body, &dcResp); err != nil {
		return "", fmt.Errorf("解析设备代码响应失败: %v (原始: %s)", err, string(body))
	}
	if dcResp.Error != "" {
		return "", fmt.Errorf("设备代码错误: %s - %s", dcResp.Error, dcResp.ErrorDescription)
	}

	// 验证页必须是 https 且落在微软自家域名，避免被劫持响应导向钓鱼站骗取 user code。
	if !isAllowedVerificationURL(dcResp.VerificationURL) {
		return "", fmt.Errorf("验证 URL 不在微软可信域名内，拒绝打开")
	}

	// 安全修复：不要走 cmd.exe /c start，那会把 URL 拼进 shell 命令行，
	// 一旦 VerificationURL 含 & 或 ^ 等 cmd 元字符就可能被解析成命令。
	// runtime.BrowserOpenURL 直接交给系统默认浏览器，不经过 shell。
	runtime.BrowserOpenURL(a.ctx, dcResp.VerificationURL)

	runtime.ClipboardSetText(a.ctx, dcResp.UserCode)

	go a.pollMicrosoftToken(dcResp)

	result := fmt.Sprintf("%s|%s", dcResp.VerificationURL, dcResp.UserCode)
	return result, nil
}
