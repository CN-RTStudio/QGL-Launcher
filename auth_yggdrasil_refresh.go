package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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

// DownloadAuthlibInjector 下载并强校验 authlib-injector.jar（javaagent，可执行）。
// 已存在的 jar 也必须通过侧车记录的官方 SHA-256 复核，绝不"文件在就直接用"。
func (a *App) DownloadAuthlibInjector() (string, error) {
	qglDir := a.GetQGLDir()
	jarPath := filepath.Join(qglDir, "authlib-injector.jar")
	if err := os.MkdirAll(qglDir, 0700); err != nil {
		return "", fmt.Errorf("创建目录失败: %v", err)
	}

	downloadURL, expectedSHA256, err := fetchAuthlibLatest()
	if err != nil {
		// 拿不到权威哈希时，只有"已有 jar 且侧车自证完整"才可继续离线复用；
		// 但侧车里的期望值同样来自上次官方哈希，此处无新值，保守起见要求网络可用。
		return "", err
	}

	if state := inspectRegularFile(jarPath); state.trustable() {
		if verifyAuthlibJar(jarPath, expectedSHA256) {
			return jarPath, nil
		}
		// 已存在但哈希不符 / 无侧车：可能被篡改或是旧版本，删除后重下。
		os.Remove(jarPath)
		removeAuthlibMeta(jarPath)
	}

	mirrorURL := strings.ReplaceAll(downloadURL,
		"authlib-injector.yushi.moe",
		"bmclapi2.bangbang93.com/mirrors/authlib-injector")
	candidates := []string{downloadURL}
	if isAllowedAuthlibDownloadURL(mirrorURL) && mirrorURL != downloadURL {
		candidates = append(candidates, mirrorURL)
	}
	if err := downloadAuthlibJarFromCandidates(jarPath, candidates, expectedSHA256); err != nil {
		return "", err
	}
	return jarPath, nil
}
