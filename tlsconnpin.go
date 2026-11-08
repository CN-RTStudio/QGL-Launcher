package main

// tlsconnpin.go —— 关键端点的 SPKI 证书固定（public key pinning）裁决内核。
//
// 为什么在“系统根证书校验通过”之外还要固定：
//   启动器会向 Mojang 会话/认证、Modrinth 等端点提交或接收凭据与令牌。仅信任
//   系统根库时，任何被植入的根 CA、被胁迫签发的证书、或企业代理都能以“合法
//   证书”中间人这些连接。SPKI 固定要求对端叶子/链上证书公钥指纹落在预置的
//   主/备指纹集合内，否则即使证书链合法也拒绝（HPKP 已废弃为响应头，桌面应用
//   仍可在客户端本地做静态固定，且没有 HPKP 的“可被恶意锁死”问题，因为指纹
//   随程序发布、可随版本更新轮换）。
//
// 安全细节：
//   - 必须同时配置主指纹与至少一个备份指纹，避免“唯一指纹轮换即断网/被迫关闭
//     校验”；
//   - 指纹集带 NotAfter：过期后不再强制阻断（防止旧版本被永久锁死），仅告警；
//   - ReportOnly 模式只记录不阻断，用于灰度观察；
//   - 主机匹配默认精确，允许单标签通配 "*.example.com"（字符匹配，不用正则）。

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"
)

const (
	PinReasonNoPin            = "pin-not-configured"
	PinReasonMatchedPrimary   = "pin-matched-primary"
	PinReasonMatchedBackup    = "pin-matched-backup"
	PinReasonNoMatch          = "pin-no-matching-spki"
	PinReasonNoCerts          = "pin-no-peer-certificates"
	PinReasonSetInvalid       = "pin-set-invalid"
	PinReasonExpiredNotBlock  = "pin-set-expired-monitor-only"
	PinReasonReportOnly       = "pin-report-only-mismatch"
)

// SPKIPinSet 是某个主机的一组可信公钥指纹（小写十六进制 SHA-256 of DER SPKI）。
type SPKIPinSet struct {
	Host        string   // 精确主机，如 api.modrinth.com；或单标签通配 *.example.com
	Primary     []string // 主指纹（至少 1）
	Backup      []string // 备份指纹（至少 1，用于轮换）
	NotAfter    time.Time
	ReportOnly  bool
}

// PinVerdict 是固定校验结论。
type PinVerdict struct {
	Host     string
	Allowed  bool
	Enforced bool   // 该指纹集是否处于强制（非过期、非 report-only）状态
	Reason   string
	Matched  string // 命中的指纹（小写 hex），未命中为空
}

// NormalizeSPKIHex 把指纹统一为小写并做形状校验（64 hex，无空白/冒号）。
func NormalizeSPKIHex(v string) (string, bool) {
	v = strings.TrimSpace(strings.ToLower(v))
	if len(v) != 64 {
		return "", false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", false
		}
	}
	return v, true
}

// ValidatePinSet 校验一个指纹集自身是否可用（主/备齐全、指纹形状合法、主机非空）。
func ValidatePinSet(p SPKIPinSet) (string, bool) {
	host := strings.ToLower(strings.TrimSpace(p.Host))
	if host == "" {
		return PinReasonSetInvalid, false
	}
	if len(p.Primary) == 0 || len(p.Backup) == 0 {
		return PinReasonSetInvalid, false
	}
	all := append(append([]string{}, p.Primary...), p.Backup...)
	seen := make(map[string]struct{}, len(all))
	for _, raw := range all {
		n, ok := NormalizeSPKIHex(raw)
		if !ok {
			return PinReasonSetInvalid, false
		}
		if _, dup := seen[n]; dup {
			return PinReasonSetInvalid, false
		}
		seen[n] = struct{}{}
	}
	return "", true
}

// SPKIFingerprint 计算证书 SubjectPublicKeyInfo 的 SHA-256（小写 hex）。
func SPKIFingerprint(cert *x509.Certificate) string {
	if cert == nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// hostMatchesPin 做精确或单标签通配匹配（*.x 匹配 a.x，不匹配 a.b.x，不匹配 x 自身）。
func hostMatchesPin(pinHost, host string) bool {
	pinHost = strings.ToLower(pinHost)
	host = strings.ToLower(host)
	if pinHost == host {
		return true
	}
	if !strings.HasPrefix(pinHost, "*.") {
		return false
	}
	suffix := pinHost[1:] // ".example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	left := host[:len(host)-len(suffix)] // 通配位，如 "a."
	if left == "" || strings.Contains(left, ".") {
		return false
	}
	return true
}

// findPinSet 选出与主机匹配的指纹集；多个匹配时优先精确主机。
func findPinSet(host string, pins []SPKIPinSet) (SPKIPinSet, bool) {
	var wildcard *SPKIPinSet
	for _, p := range pins {
		h := strings.ToLower(strings.TrimSpace(p.Host))
		if h == strings.ToLower(host) {
			return p, true
		}
		if strings.HasPrefix(h, "*.") && wildcard == nil && hostMatchesPin(h, host) {
			pc := p
			wildcard = &pc
		}
	}
	if wildcard != nil {
		return *wildcard, true
	}
	return SPKIPinSet{}, false
}

// EvaluatePins 用已握手连接的证书链做固定校验。
func EvaluatePins(host string, state *tls.ConnectionState, pins []SPKIPinSet, now time.Time) PinVerdict {
	v := PinVerdict{Host: host, Allowed: true, Enforced: false}
	set, ok := findPinSet(host, pins)
	if !ok {
		v.Reason = PinReasonNoPin
		return v
	}
	if _, valid := ValidatePinSet(set); !valid {
		v.Allowed = false
		v.Reason = PinReasonSetInvalid
		return v
	}
	v.Enforced = true
	expired := !set.NotAfter.IsZero() && now.After(set.NotAfter)

	if state == nil || len(state.PeerCertificates) == 0 {
		if !expired && !set.ReportOnly {
			v.Allowed = false
		}
		v.Reason = PinReasonNoCerts
		if expired {
			v.Reason = PinReasonExpiredNotBlock
			v.Allowed = true
			v.Enforced = false
		}
		return v
	}

	matched := ""
	matchedKind := ""
	for _, cert := range state.PeerCertificates {
		fp := SPKIFingerprint(cert)
		if containsNorm(set.Primary, fp) {
			matched, matchedKind = fp, PinReasonMatchedPrimary
			break
		}
		if containsNorm(set.Backup, fp) {
			matched, matchedKind = fp, PinReasonMatchedBackup
			break
		}
	}

	if matched != "" {
		v.Matched = matched
		v.Reason = matchedKind
		v.Allowed = true
		return v
	}

	// 未命中：过期指纹集只监控不阻断；report-only 不阻断；否则拒绝。
	if expired {
		v.Allowed = true
		v.Enforced = false
		v.Reason = PinReasonExpiredNotBlock
		return v
	}
	if set.ReportOnly {
		v.Allowed = true
		v.Reason = PinReasonReportOnly
		return v
	}
	v.Allowed = false
	v.Reason = PinReasonNoMatch
	return v
}

func containsNorm(list []string, fp string) bool {
	for _, raw := range list {
		if n, ok := NormalizeSPKIHex(raw); ok && n == fp {
			return true
		}
	}
	return false
}
