package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
