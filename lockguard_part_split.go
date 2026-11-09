package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"time"
)

// ClearLaunchPIN 校验原 PIN 后清除锁（写空负载）。
func ClearLaunchPIN(store lockStore, pin string, lim LockLimits) error {
	ok, _, _ := VerifyLaunchPIN(store, pin, lim)
	if !ok {
		return errText("pin-verify-fail")
	}
	if err := store.Save(nil); err != nil {
		return errText("pin-clear-store")
	}
	return nil
}

// LockStatus 只读状态，供 UI 展示剩余次数/冷却倒计时。
func LockStatus(store lockStore, lim LockLimits) (configured bool, remaining int, locked bool, untilUnixNano int64) {
	if lim.MinPINLen == 0 {
		lim = defaultLockLimits()
	}
	raw, err := store.Load()
	if err != nil || len(raw) == 0 {
		return false, lim.MaxAttempt, false, 0
	}
	st := normalizeLockState(raw)
	now := time.Now().UnixNano()
	if st.LockedUntil > now {
		return true, 0, true, st.LockedUntil
	}
	return true, lim.MaxAttempt - st.Fails, false, 0
}

// SummarizeLockStatus 压成一行可读文本（日志/审计事件用）。
func SummarizeLockStatus(configured bool, remaining int, locked bool) string {
	if !configured {
		return "launch-lock unset"
	}
	if locked {
		return "launch-lock locked"
	}
	return "launch-lock armed remaining=" + itoaSafe(remaining)
}

func itoaSafe(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func hmacEqualHex(a, b string) bool {
	if len(a) != 64 || len(b) != 64 {
		return false
	}
	da, ea := hex.DecodeString(a)
	db, eb := hex.DecodeString(b)
	if ea != nil || eb != nil {
		return false
	}
	return subtle.ConstantTimeCompare(da, db) == 1
}

// errText 定义在 umfs.go（type errText string），这里直接复用；
// errText("...") 已满足 error 接口，无需再包装。

// base64 import guard（摘要负载可选 base64 形态时使用）
var _ = base64.StdEncoding
