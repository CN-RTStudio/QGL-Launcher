package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
func (a *App) DownloadAuthlibInjector() (string, error) {
	qglDir := a.GetQGLDir()
	jarPath := filepath.Join(qglDir, "authlib-injector.jar")

	// 如果已存在，直接返回
	if _, err := os.Stat(jarPath); err == nil {
		return jarPath, nil
	}

	if err := os.MkdirAll(qglDir, 0755); err != nil {
		return "", fmt.Errorf("创建目录失败: %v", err)
	}

	// 参考 PCL：先获取 latest.json 获取下载地址，再下载 jar
	latestURLs := []string{
		"https://authlib-injector.yushi.moe/artifact/latest.json",
		"https://bmclapi2.bangbang93.com/mirrors/authlib-injector/artifact/latest.json",
	}

	var latestInfo map[string]interface{}
	var downloadURL string

	client := &http.Client{Timeout: 15 * time.Second}
	for _, url := range latestURLs {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			if err := json.Unmarshal(body, &latestInfo); err == nil {
				if du, ok := latestInfo["download_url"].(string); ok && du != "" {
					downloadURL = du
					break
				}
			}
		}
	}

	if downloadURL == "" {
		return "", fmt.Errorf("获取 authlib-injector 下载地址失败")
	}

	// 替换为 BMCLAPI 镜像作为备用
	mirrorURL := strings.ReplaceAll(downloadURL, "authlib-injector.yushi.moe", "bmclapi2.bangbang93.com/mirrors/authlib-injector")

	downloadClient := &http.Client{Timeout: 120 * time.Second}
	var lastErr error
	for _, url := range []string{downloadURL, mirrorURL} {
		resp, err := downloadClient.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		file, err := os.Create(jarPath)
		if err != nil {
			return "", fmt.Errorf("创建文件失败: %v", err)
		}
		if _, err := io.Copy(file, resp.Body); err != nil {
			file.Close()
			os.Remove(jarPath)
			return "", fmt.Errorf("写入文件失败: %v", err)
		}
		file.Close()
		return jarPath, nil
	}

	return "", fmt.Errorf("下载 authlib-injector 失败: %v", lastErr)
}

// GetAuthlibInjectorPath 获取 authlib-injector.jar 路径（不存在则下载）
func (a *App) GetAuthlibInjectorPath() (string, error) {
	return a.DownloadAuthlibInjector()
}
