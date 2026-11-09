package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"time"
)

// SetLaunchPIN 设置/更换 PIN。prevHMAC 为空表示首次设置；非空时要求与当前
// 落盘摘要一致（防止未解锁状态下被直接改锁）。返回错误信息或空串。
func SetLaunchPIN(store lockStore, pin, prevHMAC string, lim LockLimits) error {
	if lim.MinPINLen == 0 {
		lim = defaultLockLimits()
	}
	if len(pin) < lim.MinPINLen || len(pin) > lim.MaxPINLen {
		return errText("pin-length-out-of-range")
	}
	raw, _ := store.Load()
	cur := normalizeLockState(raw)
	if prevHMAC != "" {
		if !hmacEqualHex(cur.HMACHex, prevHMAC) {
			return errText("pin-prev-mismatch")
		}
	}
	if cur.LockedUntil > time.Now().UnixNano() {
		return errText("pin-locked")
	}
	next, err := newLockState(pin)
	if err != nil {
		return errText("pin-rng")
	}
	next.Fails = 0
	next.LockedUntil = 0
	payload, err := next.marshal()
	if err != nil {
		return errText("pin-marshal")
	}
	if err := store.Save(payload); err != nil {
		return errText("pin-store")
	}
	return nil
}

// VerifyLaunchPIN 校验 PIN。返回 (ok, reason, remainingFails)。
// 失败超过上限进入冷却；冷却期内一律拒绝且不消耗次数。
func VerifyLaunchPIN(store lockStore, pin string, lim LockLimits) (bool, string, int) {
	if lim.MinPINLen == 0 {
		lim = defaultLockLimits()
	}
	if len(pin) < lim.MinPINLen || len(pin) > lim.MaxPINLen {
		return false, "pin-length-out-of-range", -1
	}
	raw, err := store.Load()
	if err != nil || len(raw) == 0 {
		return false, "pin-unset", -1
	}
	st := normalizeLockState(raw)
	now := time.Now().UnixNano()
	if st.LockedUntil > now {
		return false, "pin-locked", 0
	}
	salt, err := hex.DecodeString(st.SaltHex)
	if err != nil {
		return false, "pin-corrupt", -1
	}
	sum := umfsLockDigest([]byte(pin), salt)
	expected, err := hex.DecodeString(st.HMACHex)
	if err != nil {
		return false, "pin-corrupt", -1
	}
	if subtle.ConstantTimeCompare(sum, expected) == 1 {
		st.Fails = 0
		st.LastVerified = now
		payload, _ := st.marshal()
		_ = store.Save(payload)
		return true, "", lim.MaxAttempt
	}
	st.Fails++
	remaining := lim.MaxAttempt - st.Fails
	if remaining <= 0 {
		st.Fails = 0
		st.LockedUntil = now + lim.Cooldown.Nanoseconds()
		remaining = 0
	}
	payload, _ := st.marshal()
	_ = store.Save(payload)
	return false, "pin-wrong", remaining
}

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
