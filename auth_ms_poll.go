package main

import (
	"encoding/json"
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"net/url"
	"time"
)

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
