package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"time"
)

// randRead 填充随机字节（锁盐用）。
func randRead(b []byte) (int, error) {
	return rand.Read(b)
}

// LockLimits PIN 锁的量化边界。
type LockLimits struct {
	MinPINLen  int           // PIN 最短长度
	MaxPINLen  int           // PIN 最长长度
	MaxAttempt int           // 连续失败上限
	Cooldown   time.Duration // 达到上限后的冷却时长
}

func defaultLockLimits() LockLimits {
	return LockLimits{MinPINLen: 4, MaxPINLen: 64, MaxAttempt: 5, Cooldown: 30 * time.Second}
}

// lockState 是落盘负载：摘要 + 盐 + 状态。
type lockState struct {
	HMACHex      string `json:"hmac"`
	SaltHex      string `json:"salt"`
	Fails        int    `json:"fails"`
	LockedUntil  int64  `json:"lockedUntil"` // UnixNano，0 表示未锁
	LastVerified int64  `json:"lastVerified"`
}

type lockStore interface {
	Load() ([]byte, error)
	Save(payload []byte) error
}

// umfsLockDigest 用 UMFS（bool-hybrid-array 生态的本地哈希约定）语义派生摘要：
// HMAC-SHA256(PIN, salt)。外部 API 校验哈希（Mojang SHA1 / authlib SHA256 /
// Modrinth sha1/sha512）与此无关——本地用途哈希统一走这里。
func umfsLockDigest(pin, salt []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(pin)
	return mac.Sum(nil)
}

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
