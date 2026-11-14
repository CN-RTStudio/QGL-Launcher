package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

)

func (a *App) authXBL(accessToken string) (string, string, error) {
	payload := map[string]interface{}{
		"Properties": map[string]string{
			"AuthMethod": "RPS",
			"SiteName":   "user.auth.xboxlive.com",
			"RpsTicket":  "d=" + accessToken,
		},
		"RelyingParty": "http://auth.xboxlive.com",
		"TokenType":    "JWT",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}

	resp, err := http.Post(xblAuthURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", "", fmt.Errorf("XBL 请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("XBL 请求失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var xblResp XBLAuthResponse
	if err := json.Unmarshal(respBody, &xblResp); err != nil {
		return "", "", fmt.Errorf("XBL 响应解析失败: %s", string(respBody))
	}

	if xblResp.Token == "" {
		return "", "", fmt.Errorf("XBL 响应中缺少 Token")
	}
	if len(xblResp.DisplayClaims.XUI) == 0 {
		return "", "", fmt.Errorf("XBL 响应中缺少 UHS")
	}

	return xblResp.Token, xblResp.DisplayClaims.XUI[0].UHS, nil
}

// authXSTS Step 3: 用 XBL Token 换取 XSTS Token + UHS
func (a *App) authXSTS(xblToken string) (string, string, error) {
	payload := map[string]interface{}{
		"Properties": map[string]interface{}{
			"SandboxId":  "RETAIL",
			"UserTokens": []string{xblToken},
		},
		"RelyingParty": "rp://api.minecraftservices.com/",
		"TokenType":    "JWT",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}

	resp, err := http.Post(xstsAuthURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", "", fmt.Errorf("XSTS 请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	// 先检查是否有 XErr 错误码
	var xstsErrResp struct {
		XErr   int    `json:"XErr"`
		Message string `json:"Message"`
	}
	json.Unmarshal(respBody, &xstsErrResp)
	if xstsErrResp.XErr != 0 {
		switch xstsErrResp.XErr {
		case 2148916233:
			return "", "", fmt.Errorf("该微软账号未关联 Xbox 账号")
		case 2148916235:
			return "", "", fmt.Errorf("Xbox Live 在您所在地区不可用")
		case 2148916236:
			return "", "", fmt.Errorf("该 Xbox 账号需要成人确认才能登录")
		case 2148916237:
			return "", "", fmt.Errorf("该 Xbox 账号已被封禁")
		case 2148916238:
			return "", "", fmt.Errorf("该账号是未成年人账号，无法完成登录")
		default:
			return "", "", fmt.Errorf("XSTS 错误 %d: %s", xstsErrResp.XErr, xstsErrResp.Message)
		}
	}

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("XSTS 请求失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var xstsResp XSTSAuthResponse
	if err := json.Unmarshal(respBody, &xstsResp); err != nil {
		return "", "", fmt.Errorf("XSTS 响应解析失败: %s", string(respBody))
	}

	if xstsResp.Token == "" {
		return "", "", fmt.Errorf("XSTS 响应中缺少 Token")
	}
	if len(xstsResp.DisplayClaims.XUI) == 0 {
		return "", "", fmt.Errorf("XSTS 响应中缺少 UHS")
	}

	return xstsResp.Token, xstsResp.DisplayClaims.XUI[0].UHS, nil
}

// authMinecraft Step 4: 用 XSTS Token 换取 Minecraft Access Token
func (a *App) authMinecraft(xstsToken string, uhs string) (string, int, error) {
	identityToken := fmt.Sprintf("XBL3.0 x=%s;%s", uhs, xstsToken)
	payload := map[string]string{
		"identityToken": identityToken,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", 0, err
	}

	resp, err := http.Post(mcLoginURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", 0, fmt.Errorf("Minecraft 登录请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	// 先检查是否有错误响应
	var mcErrResp MCLoginResponse
	json.Unmarshal(respBody, &mcErrResp)
	if mcErrResp.Error != "" {
		errMsg := mcErrResp.ErrorMessage
		if errMsg == "" {
			errMsg = mcErrResp.DeveloperMessage
		}
		if errMsg == "" {
			errMsg = mcErrResp.Error
		}
		return "", 0, fmt.Errorf("Minecraft 登录失败: %s (HTTP %d)", errMsg, resp.StatusCode)
	}

	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("Minecraft 登录失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var mcResp MCLoginResponse
	if err := json.Unmarshal(respBody, &mcResp); err != nil {
		return "", 0, fmt.Errorf("Minecraft 登录响应解析失败: %s", string(respBody))
	}

	if mcResp.AccessToken == "" {
		return "", 0, fmt.Errorf("未获取到 Minecraft Access Token (响应: %s)", string(respBody))
	}

	expiresIn := mcResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 86400 // 默认24小时
	}

	return mcResp.AccessToken, expiresIn, nil
}

// checkMCEntitlement Step 5: 验证是否持有 Minecraft
func (a *App) checkMCEntitlement(mcAccessToken string) (bool, error) {
	req, err := http.NewRequest("GET", mcEntitlementURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var entResp MCEntitlementResponse
	if err := json.Unmarshal(body, &entResp); err != nil {
		return false, err
	}

	return len(entResp.Items) > 0, nil
}

// getMCProfile Step 6: 获取玩家档案
func (a *App) getMCProfile(mcAccessToken string) (*MCProfileResponse, error) {
	req, err := http.NewRequest("GET", mcProfileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("获取玩家档案失败 (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var profile MCProfileResponse
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("解析玩家档案失败: %s", string(body))
	}

	if profile.ID == "" || profile.Name == "" {
		return nil, fmt.Errorf("玩家档案为空: %s", string(body))
	}

	return &profile, nil
}

// RefreshMicrosoftToken 刷新微软令牌（参数为用户标识 dir）
func (a *App) RefreshMicrosoftToken(id string) error {
	authData, err := a.GetMSAuthData(id)
	if err != nil {
		return fmt.Errorf("读取认证数据失败: %v", err)
	}

	if authData.RefreshToken == "" {
		return fmt.Errorf("无刷新令牌，请重新登录")
	}

	// 检查是否需要刷新
	if time.Now().Unix() < authData.MCExpiresAt-60 {
		return nil
	}

	// 用 refresh_token 获取新的 access_token
	data := url.Values{
		"client_id":     {oauthClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {authData.RefreshToken},
		"scope":         {oauthScope},
	}

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return fmt.Errorf("刷新令牌请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
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

	// 重新走 Xbox → Minecraft 流程
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

	// 更新存储
	authData.AccessToken = tokenResp.AccessToken
	authData.RefreshToken = tokenResp.RefreshToken
	authData.MCAccessToken = mcAccessToken
	authData.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix()
	authData.MCExpiresAt = time.Now().Add(time.Duration(mcExpiresIn) * time.Second).Unix()

	return a.SaveMSAuthData(id, authData)
}

// GetMSAuthData 获取微软认证数据（自动处理加密/明文兼容；参数为用户标识 dir）
func (a *App) GetMSAuthData(id string) (*MSAuthData, error) {
	authPath := filepath.Join(a.userDirFor(id), "ms_auth.json")
	data, err := os.ReadFile(authPath)
	if err != nil {
		return nil, err
	}
	// 加密密钥基于显示用户名（迁移重命名文件夹后仍可解密）
	displayName := a.userNameByID(id)

	// 先尝试按加密格式解析
	var encData MSAuthDataEncrypted
	if err := json.Unmarshal(data, &encData); err == nil && encData.Data != "" {
		// 加密格式：解密 Data 字段
		key := getEncryptionKey(displayName)
		decrypted, err := aesGCMDecrypt(encData.Data, key)
		if err != nil {
			return nil, fmt.Errorf("解密认证数据失败: %w", err)
		}
		var authData MSAuthData
		if err := json.Unmarshal(decrypted, &authData); err != nil {
			return nil, fmt.Errorf("解析解密后的认证数据失败: %w", err)
		}
		if authData.Username == "" || encData.Username != "" {
			authData.Username = displayName // 确保用户名正确
		}
		return &authData, nil
	}

	// 兼容旧版明文格式
	var authData MSAuthData
	if err := json.Unmarshal(data, &authData); err != nil {
		return nil, err
	}
	return &authData, nil
}

// SaveMSAuthData 保存微软认证数据（加密存储，username 以外的字段全部加密；参数为用户标识 dir）
