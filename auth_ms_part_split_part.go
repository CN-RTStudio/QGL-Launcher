package main

import (
	"net/url"
	"strings"
	"time"
)

func clampPollInterval(seconds int) time.Duration {
	if seconds < int(deviceCodeMinInterval/time.Second) {
		return deviceCodeMinInterval
	}
	d := time.Duration(seconds) * time.Second
	if d > deviceCodeMaxInterval {
		return deviceCodeMaxInterval
	}
	return d
}

// clampDeviceTTL 钳制设备码有效期：非正用默认 5min，最大不超过 15min。
func clampDeviceTTL(seconds int) time.Duration {
	if seconds <= 0 {
		return deviceCodeDefaultTTL
	}
	d := time.Duration(seconds) * time.Second
	if d > deviceCodeMaxTTL {
		return deviceCodeMaxTTL
	}
	return d
}

// tokenExpiryUnix 根据远程给的 expires_in 计算过期时间戳。
// 非正值回退 24h（MSA/MC 令牌的常规有效期），超大值钳到一年，避免把刷新
// 判断写到错误的未来。
func tokenExpiryUnix(now time.Time, seconds int) int64 {
	if seconds <= 0 {
		seconds = tokenDefaultLifetimeSec
	}
	if seconds > tokenMaxLifetimeSeconds {
		seconds = tokenMaxLifetimeSeconds
	}
	return now.Add(time.Duration(seconds) * time.Second).Unix()
}

// isAllowedVerificationURL 限定设备码验证页只能落在微软自家域名。
// 仅校验 https:// 前缀并不够：被劫持的响应可以给一个 https:// 钓鱼站，
// 用户在系统浏览器里输入的 user code 会直接进攻击者手里。这里再收紧：
// 必须是 https、无 userinfo、主机为 microsoft.com / live.com（含子域，
// 官方设备码验证页为 www.microsoft.com/link、login.live.com 等）。
func isAllowedVerificationURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	return host == "microsoft.com" || strings.HasSuffix(host, ".microsoft.com") ||
		host == "microsoftonline.com" || strings.HasSuffix(host, ".microsoftonline.com") ||
		host == "live.com" || strings.HasSuffix(host, ".live.com")
}
