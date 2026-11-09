package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// pollMicrosoftToken 轮询微软令牌，到达设备码过期时间后自动退出。
//
// 韧性处理（interval / ttl 已在 clampXxx 中钳制）：
//   - 网络错误、5xx、429 属于瞬时故障，按翻倍退避重试，并尊重 Retry-After；
//   - 连续 deviceCodeMaxTransientErrors 次瞬时故障就报错退出，不无限忙轮询；
//   - authorization_pending / slow_down 说明服务器本身健康，清零瞬时故障计数。
func (a *App) pollMicrosoftToken(dc DeviceCodeResponse) {
	interval := clampPollInterval(dc.Interval)
	deadline := time.Now().Add(clampDeviceTTL(dc.ExpiresIn))
	slowDowns := 0
	transientErrors := 0

	// sleepFor 等待下一次轮询；应用退出（ctx.Done）时立即结束。
	// 返回 false 表示已到截止时间或应用关闭，调用方应退出循环。
	sleepFor := func(d time.Duration) bool {
		if d > deviceCodeMaxInterval {
			d = deviceCodeMaxInterval
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-a.ctx.Done():
			return false
		}
		if time.Now().After(deadline) {
			return false
		}
		return true
	}

	failTransient := func() bool {
		transientErrors++
		return transientErrors >= deviceCodeMaxTransientErrors
	}

	for {
		if !sleepFor(interval) {
			if a.ctx.Err() != nil {
				return
			}
			runtime.EventsEmit(a.ctx, "msLoginError", "登录已过期，请重新尝试")
			return
		}
		data := url.Values{
			"client_id":   {oauthClientID},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {dc.DeviceCode},
		}
		resp, err := httpClient.PostForm(tokenURL, data)
		if err != nil {
			if failTransient() {
				runtime.EventsEmit(a.ctx, "msLoginError", "登录服务器连续无响应，请检查网络后重试")
				return
			}
			interval = backoffDeviceInterval(interval)
			continue
		}

		// 429 / 5xx：优先尊重 Retry-After，否则指数退避；都不消费设备码语义。
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			retry := parseRetryAfterDelay(resp.Header.Get("Retry-After"))
			resp.Body.Close()
			if failTransient() {
				runtime.EventsEmit(a.ctx, "msLoginError", "登录服务器暂时不可用，请稍后重试")
				return
			}
			if retry > 0 {
				interval = retry
			} else {
				interval = backoffDeviceInterval(interval)
			}
			continue
		}

		body, readErr := readAuthJSON(resp)
		resp.Body.Close()
		var tokenResp TokenResponse
		if readErr != nil || json.Unmarshal(body, &tokenResp) != nil {
			// 4xx 还返回无法解析的内容，基本是被代理/门户劫持，直接失败；
			// 2xx 但内容畸形则按瞬时故障退避重试。
			if resp.StatusCode >= 400 || failTransient() {
				runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("登录响应异常 (HTTP %d)", resp.StatusCode))
				return
			}
			interval = backoffDeviceInterval(interval)
			continue
		}
		transientErrors = 0

		if tokenResp.Error != "" {
			if tokenResp.Error == "authorization_pending" {
				continue
			}
			if tokenResp.Error == "slow_down" {
				// 每次 +5s，但有总次数上限；到上限按设备码过期处理，
				// 防止服务器持续 slow_down 把 goroutine 无限挂住。
				if slowDowns >= deviceCodeMaxSlowDowns {
					runtime.EventsEmit(a.ctx, "msLoginError", "登录轮询超时，请重新尝试")
					return
				}
				slowDowns++
				interval += 5 * time.Second
				if interval > deviceCodeMaxInterval {
					interval = deviceCodeMaxInterval
				}
				continue
			}
			if tokenResp.Error == "expired_token" {
				runtime.EventsEmit(a.ctx, "msLoginError", "登录已过期，请重新尝试")
				return
			}
			runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("登录失败: %s", tokenResp.ErrorDescription))
			return
		}
		a.completeMicrosoftLogin(tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
		return
	}
}

// completeMicrosoftLogin 完成微软登录的后续步骤（Xbox → Minecraft）
func (a *App) completeMicrosoftLogin(msAccessToken string, msRefreshToken string, msExpiresIn int) {
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在验证 Xbox Live...")
	xblToken, _, err := a.authXBL(msAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("Xbox Live 验证失败: %v", err))
		return
	}
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在获取 XSTS 令牌...")
	xstsToken, xstsUHS, err := a.authXSTS(xblToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("XSTS 验证失败: %v", err))
		return
	}
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在登录 Minecraft...")
	mcAccessToken, mcExpiresIn, err := a.authMinecraft(xstsToken, xstsUHS)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("Minecraft 登录失败: %v", err))
		return
	}
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在验证游戏所有权...")
	hasGame, err := a.checkMCEntitlement(mcAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("验证游戏所有权失败: %v", err))
		return
	}
	if !hasGame {
		runtime.EventsEmit(a.ctx, "msLoginError", "该微软账号未购买 Minecraft Java 版，或 Xbox Game Pass 已过期")
		return
	}
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在获取玩家档案...")
	profile, err := a.getMCProfile(mcAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("获取玩家档案失败: %v", err))
		return
	}

	now := time.Now()
	authData := MSAuthData{
		AccessToken:   msAccessToken,
		RefreshToken:  msRefreshToken,
		MCAccessToken: mcAccessToken,
		UUID:          profile.ID,
		Username:      profile.Name,
		// MSA 令牌与 MC 令牌各自独立，过期时间必须分别记录：
		// ExpiresAt 用微软令牌 expires_in，MCExpiresAt 用 MC 登录返回的值。
		ExpiresAt:   tokenExpiryUnix(now, msExpiresIn),
		MCExpiresAt: tokenExpiryUnix(now, mcExpiresIn),
	}

	if err := a.CreatePremiumUser(profile.Name, authData); err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("创建用户失败: %v", err))
		return
	}

	if err := a.SetCurrentUser(profile.Name); err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("设置当前用户失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginSuccess", profile.Name)
}

// authXBL Step 2: 用 OAuth Token 换取 XBL Token
