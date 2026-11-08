package main

// yggsession.go —— 正版会话（Yggdrasil / 微软账户）令牌生命周期守卫内核。
//
// 威胁模型：启动器把微软/Yggdrasil 的 access token、refresh token 落盘供下次
// 启动复用。历史代码只做"存在即用"：
//  1. 过期 token 直接拿去换游戏票，换来 401 后被动等 Mojang 端错误，无法预判
//     会话何时失效，用户开着启动器却发现"已过期，请重新登录"；
//  2. refresh token 可无限刷新：如果启动器每次启动都刷一次，微软端点会把
//     长期不活跃的 refresh token 作废（设备受限 / 速率限制），反而加速失效；
//  3. 会话文件被外部改成畸形结构（缺失字段、超长字段、控制字符）时，
//     解析层可能 panic 或把垃圾写回磁盘。
//
// 本模块提供纯函数内核：
//   - 过期预检：按时间余量给出 refresh-needed / expiring-soon / ok 三级决策；
//   - 刷新节流：同一会话在时间窗口内最多刷新 N 次，超出后拒绝刷新并提示
//     重新登录（防 token 刷新风暴，也防恶意渲染层反复触发刷新）；
//   - 结构校验：会话记录必填字段、类型、长度、字符集白名单校验，畸形即拒。
// 不包含任何网络请求；接线方在拿到决策后才调用真实刷新。

import (
	"strconv"
	"strings"
	"time"
)

const (
	// yggExpireSoonWindow 到期前多久视为"即将过期"。
	yggExpireSoonWindow = 15 * time.Minute
	// yggRefreshWindow 刷新节流窗口。
	yggRefreshWindow = 24 * time.Hour
	// yggMaxRefreshesPerWindow 窗口内最大刷新次数。
	yggMaxRefreshesPerWindow = 3
	// yggMaxFieldLen 会话字段长度上限（微软 token 通常 1-2 KB）。
	yggMaxFieldLen = 8192
	// yggMinExpiryMargin 判定 refresh-needed 的最小余量。
	yggMinExpiryMargin = 5 * time.Minute
)

// YggLifecycle 是会话生命周期的三级决策。
type YggLifecycle string

const (
	YggLifecycleOK            YggLifecycle = "ok"             // 可用，无需动作
	YggLifecycleExpiringSoon  YggLifecycle = "expiring-soon"  // 即将过期，可后台预刷新
	YggLifecycleRefreshNeeded YggLifecycle = "refresh-needed" // 已过期 / 余量不足，必须刷新
	YggLifecycleInvalid       YggLifecycle = "invalid"        // 结构校验失败，需重新登录
)

// YggSessionRecord 是启动器落盘的会话记录（抽象结构，与 auth.go 解耦）。
type YggSessionRecord struct {
	AccountName  string    `json:"accountName"`
	ExpiresAt    time.Time `json:"expiresAt"`
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken,omitempty"`
}

// YggTokenRefreshes 记录某会话的刷新历史（按 accountName 聚合，内存态）。
type YggTokenRefreshes struct {
	WindowStart time.Time
	Count       int
}

// yggRefreshRegistry 是刷新节流的内存登记表。
type yggRefreshRegistry struct {
	entries map[string]YggTokenRefreshes
}

func newYggRefreshRegistry() *yggRefreshRegistry {
	return &yggRefreshRegistry{entries: make(map[string]YggTokenRefreshes)}
}

// AllowRefresh 决定是否允许刷新；窗口过期则重置计数。
func (r *yggRefreshRegistry) AllowRefresh(account string, now time.Time) (bool, int) {
	if account == "" {
		return false, 0
	}
	prev, ok := r.entries[account]
	if !ok || now.Sub(prev.WindowStart) >= yggRefreshWindow {
		r.entries[account] = YggTokenRefreshes{WindowStart: now, Count: 1}
		return true, 1
	}
	if prev.Count >= yggMaxRefreshesPerWindow {
		return false, prev.Count
	}
	prev.Count++
	r.entries[account] = prev
	return true, prev.Count
}

// ResetRefreshes 显式清空某会话的刷新计数（用户重新登录成功后调用）。
func (r *yggRefreshRegistry) ResetRefreshes(account string) {
	delete(r.entries, account)
}

// ValidateSessionRecord 校验会话记录结构：字段类型、长度、字符集、时间合理性。
// 返回 (是否有效, 失败原因)。畸形记录必须拒绝使用，避免把垃圾写回磁盘。
func ValidateSessionRecord(rec YggSessionRecord) (bool, string) {
	if rec.AccountName == "" {
		return false, "accountName is empty"
	}
	if len(rec.AccountName) > 256 {
		return false, "accountName too long"
	}
	if len(rec.AccessToken) == 0 || len(rec.AccessToken) > yggMaxFieldLen {
		return false, "accessToken length out of range"
	}
	if len(rec.RefreshToken) > yggMaxFieldLen {
		return false, "refreshToken too long"
	}
	for _, s := range []string{rec.AccountName, rec.AccessToken, rec.RefreshToken} {
		for _, r := range s {
			if r < 0x20 || r == 0x7f {
				return false, "control character in session field"
			}
		}
	}
	if rec.ExpiresAt.IsZero() {
		return false, "expiresAt is zero"
	}
	if rec.ExpiresAt.Before(time.Now().Add(-24 * time.Hour)) {
		// 过期超过一天：直接判定需要重新登录，不再尝试刷新旧会话。
		return false, "session expired long ago"
	}
	return true, ""
}

// DecideLifecycle 根据当前时间与过期时间给出生命周期决策。
// 注意：调用方应先做结构校验；本函数假定结构有效。
func DecideLifecycle(expiresAt, now time.Time) YggLifecycle {
	remain := expiresAt.Sub(now)
	switch {
	case remain <= 0:
		return YggLifecycleRefreshNeeded
	case remain < yggMinExpiryMargin:
		return YggLifecycleRefreshNeeded
	case remain < yggExpireSoonWindow:
		return YggLifecycleExpiringSoon
	default:
		return YggLifecycleOK
	}
}

// TokenFingerprint 生成令牌脱敏指纹（前 4 + 后 4 + 长度），供审计留痕。
// 指纹不含令牌本体，可安全进入日志 / 审计事件。
func TokenFingerprint(token string) string {
	if token == "" {
		return "(none)"
	}
	if len(token) <= 12 {
		return "(short)"
	}
	return token[:4] + "…" + token[len(token)-4:] + "(" + strconv.Itoa(len(token)) + ")"
}

// NextRefreshAllowedAt 返回下次允许刷新的时间（节流窗口结束点）。
func NextRefreshAllowedAt(account string, reg *yggRefreshRegistry, now time.Time) time.Time {
	if reg == nil {
		return now
	}
	prev, ok := reg.entries[account]
	if !ok || now.Sub(prev.WindowStart) >= yggRefreshWindow {
		return now
	}
	return prev.WindowStart.Add(yggRefreshWindow)
}

// sanitizeSessionName 清理账号名（剥控制字符、截断），用于落盘与展示。
func sanitizeSessionName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}
