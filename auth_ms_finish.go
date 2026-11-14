package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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

// backoffDeviceInterval 把轮询间隔翻倍退避（下限 5s、上限 5min）。
func backoffDeviceInterval(cur time.Duration) time.Duration {
	next := cur * 2
	if next < deviceCodeMinInterval {
		return deviceCodeMinInterval
	}
	if next > deviceCodeMaxInterval {
		return deviceCodeMaxInterval
	}
	return next
}

// parseRetryAfterDelay 解析 RFC 7231 的 Retry-After（delta-seconds 或 HTTP 日期），
// 非法 / 零 / 负值返回 0；正值统一钳到轮询上限，避免服务器让我们睡几个小时。
func parseRetryAfterDelay(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if sec, err := strconv.Atoi(value); err == nil {
		if sec <= 0 {
			return 0
		}
		d := time.Duration(sec) * time.Second
		if d > deviceCodeMaxInterval {
			return deviceCodeMaxInterval
		}
		return d
	}
	if t, err := http.ParseTime(value); err == nil {
		d := time.Until(t)
		if d <= 0 || d > deviceCodeMaxInterval {
			if d <= 0 {
				return 0
			}
			return deviceCodeMaxInterval
		}
		return d
	}
	return 0
}
