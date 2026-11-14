package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"syscall"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) StartMicrosoftLogin() (string, error) {
	// Step 1: 请求设备代码
	data := url.Values{
		"client_id": {oauthClientID},
		"scope":     {oauthScope},
	}

	resp, err := http.PostForm(deviceCodeURL, data)
	if err != nil {
		return "", fmt.Errorf("请求设备代码失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
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

	// 自动打开验证链接
	openCmd := exec.Command("cmd", "/c", "start", dcResp.VerificationURL)
	openCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	openCmd.Start()

	// 自动复制用户代码到剪贴板
	runtime.ClipboardSetText(a.ctx, dcResp.UserCode)

	// 在后台轮询令牌
	go a.pollMicrosoftToken(dcResp)

	// 返回用户需要访问的URL和代码
	result := fmt.Sprintf("%s|%s", dcResp.VerificationURL, dcResp.UserCode)
	return result, nil
}

// pollMicrosoftToken 轮询微软令牌
