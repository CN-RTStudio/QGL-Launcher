package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) pollMicrosoftToken(dc DeviceCodeResponse) {
	interval := 5
	if dc.Interval > 0 {
		interval = dc.Interval
	}

	for {
		time.Sleep(time.Duration(interval) * time.Second)

		data := url.Values{
			"client_id":   {oauthClientID},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {dc.DeviceCode},
		}

		resp, err := http.PostForm(tokenURL, data)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var tokenResp TokenResponse
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			continue
		}

		if tokenResp.Error != "" {
			if tokenResp.Error == "authorization_pending" {
				continue
			}
			if tokenResp.Error == "slow_down" {
				interval += 5
				continue
			}
			if tokenResp.Error == "expired_token" {
				runtime.EventsEmit(a.ctx, "msLoginError", "登录已过期，请重新尝试")
				return
			}
			runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("登录失败: %s", tokenResp.ErrorDescription))
			return
		}

		// 获取到 Microsoft Access Token，继续后续步骤
		a.completeMicrosoftLogin(tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
		return
	}
}

// completeMicrosoftLogin 完成微软登录的后续步骤（Xbox → Minecraft）
func (a *App) completeMicrosoftLogin(msAccessToken string, msRefreshToken string, msExpiresIn int) {
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在验证 Xbox Live...")

	// Step 2: OAuth Token → XBL Token
	xblToken, _, err := a.authXBL(msAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("Xbox Live 验证失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在获取 XSTS 令牌...")

	// Step 3: XBL Token → XSTS Token + UHS
	xstsToken, xstsUHS, err := a.authXSTS(xblToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("XSTS 验证失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在登录 Minecraft...")

	// Step 4: XSTS Token → Minecraft Access Token
	// 注意：使用 XSTS 返回的 UHS，而不是 XBL 的 UHS
	mcAccessToken, mcExpiresIn, err := a.authMinecraft(xstsToken, xstsUHS)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("Minecraft 登录失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在验证游戏所有权...")

	// Step 5: 验证是否持有 Minecraft
	hasGame, err := a.checkMCEntitlement(mcAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("验证游戏所有权失败: %v", err))
		return
	}
	if !hasGame {
		runtime.EventsEmit(a.ctx, "msLoginError", "该微软账号未购买 Minecraft Java 版，或 Xbox Game Pass 已过期")
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在获取玩家档案...")

	// Step 6: 获取玩家档案
	profile, err := a.getMCProfile(mcAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("获取玩家档案失败: %v", err))
		return
	}

	// 保存认证数据
	authData := MSAuthData{
		AccessToken:   msAccessToken,
		RefreshToken:  msRefreshToken,
		MCAccessToken: mcAccessToken,
		UUID:          profile.ID,
		Username:      profile.Name,
		ExpiresAt:     time.Now().Add(time.Duration(msExpiresIn) * time.Second).Unix(),
		MCExpiresAt:   time.Now().Add(time.Duration(mcExpiresIn) * time.Second).Unix(),
	}

	// 创建正版用户（返回用户标识 dir）
	dir, err := a.CreatePremiumUser(profile.Name, authData)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("创建用户失败: %v", err))
		return
	}

	// 设置为当前用户
	if err := a.SetCurrentUser(dir); err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("设置当前用户失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginSuccess", profile.Name)
}

// authXBL Step 2: 用 OAuth Token 换取 XBL Token
