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

func (a *App) SaveMSAuthData(id string, authData *MSAuthData) error {
	userDir := a.userDirFor(id)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return err
	}
	displayName := a.userNameByID(id)

	// 构建需要加密的数据（除 username 以外的所有字段）
	encryptPayload := map[string]interface{}{
		"accessToken":   authData.AccessToken,
		"refreshToken":  authData.RefreshToken,
		"mcAccessToken": authData.MCAccessToken,
		"uuid":          authData.UUID,
		"expiresAt":     authData.ExpiresAt,
		"mcExpiresAt":   authData.MCExpiresAt,
	}
	payloadBytes, err := json.Marshal(encryptPayload)
	if err != nil {
		return err
	}

	// 加密（密钥基于显示用户名）
	key := getEncryptionKey(displayName)
	encrypted, err := aesGCMEncrypt(payloadBytes, key)
	if err != nil {
		return fmt.Errorf("加密认证数据失败: %w", err)
	}

	// 构建加密后的存储格式
	encData := MSAuthDataEncrypted{
		Username: displayName,
		Data:     encrypted,
	}

	data, err := json.MarshalIndent(encData, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(userDir, "ms_auth.json"), data, 0644)
}

// ===== Yggdrasil 外置登录 =====

// YggdrasilAuthResponse Yggdrasil 认证响应
type YggdrasilAuthResponse struct {
	AccessToken      string `json:"accessToken"`
	ClientToken      string `json:"clientToken"`
	AvailableProfiles []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"availableProfiles"`
	SelectedProfile *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"selectedProfile"`
	Error            string `json:"error"`
	ErrorMessage     string `json:"errorMessage"`
	Cause            string `json:"cause"`
}

// YggdrasilServerMeta Yggdrasil 服务器元信息
type YggdrasilServerMeta struct {
	ServerName string `json:"serverName"`
}

// YggdrasilServerLinks Yggdrasil 服务器链接
type YggdrasilServerLinks struct {
	Homepage string `json:"homepage"`
	Register string `json:"register"`
}

// YggdrasilServerInfo Yggdrasil 服务器信息
type YggdrasilServerInfo struct {
	Meta  YggdrasilServerMeta  `json:"meta"`
	Links YggdrasilServerLinks `json:"links"`
}

// normalizeYggdrasilURL 规范化 Yggdrasil 服务器地址
func normalizeYggdrasilURL(serverURL string) string {
	serverURL = strings.TrimSpace(serverURL)
	serverURL = strings.TrimSuffix(serverURL, "/")
	// 如果不以 /api/yggdrasil 结尾，自动添加
	if !strings.HasSuffix(serverURL, "/api/yggdrasil") {
		serverURL = serverURL + "/api/yggdrasil"
	}
	return serverURL
}

// GetYggdrasilServerInfo 获取 Yggdrasil 服务器信息
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
