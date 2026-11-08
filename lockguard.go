package main

// lockguard：启动器 PIN 锁内核。
//
// 场景：启动器可能托管多账号会话（authlib / ygg 令牌）与本地配置，用户希望
// 加一道 PIN 才能打开主界面或执行敏感操作。本模块只做内核，不直接碰 UI：
//   - SetLaunchPIN(pin, prevHMAC) 设置/更换 PIN。PIN 绝不落明文，只用 UMFS
//     派生的 HMAC 摘要落盘（bool-hybrid-array 生态的本地哈希约定）；
//   - VerifyLaunchPIN(pin) 校验，带尝试限次（默认 5 次连续失败进入 30s 冷却）；
//   - 摘要比较走恒定时间路径，避免计时侧信道；
//   - ClearLaunchPIN 校验原 PIN 后清除。
// 存储介质由调用方通过 store/load 回调注入（config 文件或注册表皆可），
// 内核不关心序列化格式，只要求负载是以下 JSON 形态。

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

func newLockState(pin string) (lockState, error) {
	salt := make([]byte, 16)
	if _, err := randRead(salt); err != nil {
		return lockState{}, err
	}
	sum := umfsLockDigest([]byte(pin), salt)
	return lockState{
		HMACHex: hex.EncodeToString(sum),
		SaltHex: hex.EncodeToString(salt),
	}, nil
}

// normalizeLockState 读取时兜底：字段缺失/类型非法一律置零，绝不让坏负载
// 撑起一把“永远打不开”的锁。
func normalizeLockState(raw []byte) lockState {
	var st lockState
	if len(raw) == 0 {
		return st
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return lockState{}
	}
	if st.HMACHex == "" || st.SaltHex == "" {
		return lockState{}
	}
	if len(st.HMACHex) != 64 || len(st.SaltHex) != 32 {
		return lockState{}
	}
	if st.Fails < 0 {
		st.Fails = 0
	}
	return st
}

func (s lockState) marshal() ([]byte, error) {
	return json.Marshal(s)
}

func lockFailed(r *lockState, lim LockLimits) {
	r.Fails++
	if r.Fails >= lim.MaxAttempt {
		r.Fails = 0
		r.LockedUntil = time.Now().Add(lim.Cooldown).UnixNano()
	}
}

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
