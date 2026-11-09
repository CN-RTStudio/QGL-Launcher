package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

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

// checkMCEntitlement Step 5: 验证是否持有 Minecraft
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

// getMCProfile Step 6: 获取玩家档案
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

// RefreshMicrosoftToken 刷新微软令牌
