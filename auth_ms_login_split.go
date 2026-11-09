package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

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
