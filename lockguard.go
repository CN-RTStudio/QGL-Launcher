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
