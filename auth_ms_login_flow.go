package main

import (
	"encoding/json"
	"fmt"
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
	resp, err := httpClient.Post(xblAuthURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", "", fmt.Errorf("XBL 请求失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := readAuthJSON(resp)
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

func (a *App) authMinecraft(xstsToken string, uhs string) (string, int, error) {
	identityToken := fmt.Sprintf("XBL3.0 x=%s;%s", uhs, xstsToken)
	payload := map[string]string{
		"identityToken": identityToken,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", 0, err
	}
	resp, err := httpClient.Post(mcLoginURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", 0, fmt.Errorf("Minecraft 登录请求失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := readAuthJSON(resp)
	if err != nil {
		return "", 0, err
	}
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
		expiresIn = 86400
	}
	return mcResp.AccessToken, expiresIn, nil
}

func (a *App) checkMCEntitlement(mcAccessToken string) (bool, error) {
	req, err := http.NewRequest("GET", mcEntitlementURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := readAuthJSON(resp)
	if err != nil {
		return false, err
	}
	var entResp MCEntitlementResponse
	if err := json.Unmarshal(body, &entResp); err != nil {
		return false, err
	}
	return len(entResp.Items) > 0, nil
}

func (a *App) getMCProfile(mcAccessToken string) (*MCProfileResponse, error) {
	req, err := http.NewRequest("GET", mcProfileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := readAuthJSON(resp)
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

func (a *App) RefreshMicrosoftToken(username string) error {
	if !authRateLimiter.Allow("ms-refresh-" + username) {
		return fmt.Errorf("刷新令牌过于频繁，请稍后再试")
	}
	if err := validateUsername(username); err != nil {
		return err
	}
	authData, err := a.GetMSAuthData(username)
	if err != nil {
		return fmt.Errorf("读取认证数据失败: %v", err)
	}
	if authData.RefreshToken == "" {
		return fmt.Errorf("无刷新令牌，请重新登录")
	}
	if time.Now().Unix() < authData.MCExpiresAt-60 {
		return nil
	}
	data := url.Values{
		"client_id":     {oauthClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {authData.RefreshToken},
		"scope":         {oauthScope},
	}
	resp, err := httpClient.PostForm(tokenURL, data)
	if err != nil {
		return fmt.Errorf("刷新令牌请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, err := readAuthJSON(resp)
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
	now := time.Now()
	authData.AccessToken = tokenResp.AccessToken
	// 微软刷新响应可能不重复下发 refresh_token（令牌轮转但本响应缺字段）；
	// 此时绝不能用空串覆盖掉旧的 refresh_token，否则下一次刷新会直接废掉。
	if tokenResp.RefreshToken != "" {
		authData.RefreshToken = tokenResp.RefreshToken
	}
	authData.MCAccessToken = mcAccessToken
	authData.ExpiresAt = tokenExpiryUnix(now, tokenResp.ExpiresIn)
	authData.MCExpiresAt = tokenExpiryUnix(now, mcExpiresIn)
	return a.SaveMSAuthData(username, authData)
}

func (a *App) GetMSAuthData(username string) (*MSAuthData, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	authPath := filepath.Join(a.GetUsersDir(), username, "ms_auth.json")
	// 凭据文件走有界读取（默认 64MiB 本地文本上限）并拒绝符号链接，防止超大 / 预置链接读入。
	data, err := readBoundedFile(authPath, localTextConfigMaxBytes)
	if err != nil {
		return nil, err
	}
	var encData MSAuthDataEncrypted
	if err := json.Unmarshal(data, &encData); err == nil && encData.Data != "" {
		saltPath := filepath.Join(a.GetUsersDir(), username, "ms_auth.salt")
		salt, _, _ := loadOrCreateAuthSalt(saltPath, false)
		key := getEncryptionKey(username, salt)
		decrypted, err := aesGCMDecrypt(encData.Data, key)
		if err != nil {
			return nil, fmt.Errorf("解密认证数据失败: %w", err)
		}
		var authData MSAuthData
		if err := json.Unmarshal(decrypted, &authData); err != nil {
			return nil, fmt.Errorf("解析解密后的认证数据失败: %w", err)
		}
		authData.Username = username
		return &authData, nil
	}
	var authData MSAuthData
	if err := json.Unmarshal(data, &authData); err != nil {
		return nil, fmt.Errorf("解析认证数据失败: %w", err)
	}
	return &authData, nil
}

func (a *App) SaveMSAuthData(username string, authData *MSAuthData) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return err
	}
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
	saltPath := filepath.Join(userDir, "ms_auth.salt")
	salt, _, _ := loadOrCreateAuthSalt(saltPath, true)
	key := getEncryptionKey(username, salt)
	encrypted, err := aesGCMEncrypt(payloadBytes, key)
	if err != nil {
		return fmt.Errorf("加密认证数据失败: %w", err)
	}
	encData := MSAuthDataEncrypted{
		Username: username,
		Data:     encrypted,
	}
	data, err := json.MarshalIndent(encData, "", "  ")
	if err != nil {
		return err
	}
	// 微软令牌是最高敏感级数据：原子写、0600、拒绝符号链接写穿
	return secureWritePrivateFile(filepath.Join(userDir, "ms_auth.json"), data)
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
	resp, err := httpClient.Post(xstsAuthURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", "", fmt.Errorf("XSTS 请求失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := readAuthJSON(resp)
	if err != nil {
		return "", "", err
	}
	var xstsErrResp struct {
		XErr    int    `json:"XErr"`
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
