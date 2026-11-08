package main

// tlssecuritypolicy.go —— 出向 TLS 连接的版本 / 加密套件 / 协商参数安全基线。
//
// 启动器与 Mojang、Modrinth、镜像源之间全部走 HTTPS。Go 默认允许较老的协议
// 版本与弱套件，在“被强制降级 / 老旧镜像 / 中间人”场景下可能协商出：
//   - TLS 1.0 / 1.1（已废弃，CBC+MAC 易受 BEAST/填充攻击）；
//   - 3DES、RC4、匿名套件、空加密、EXPORT；
//   - 无对端证书、非 AEAD 套件（严格模式下应拒绝）。
//
// 证书链有效期、主机名校验放在 certvalidityguard.go，SPKI 固定放在
// tlsconnpin.go；本模块只做“已协商参数是否达到基线”的纯裁决，输入是
// *tls.ConnectionState，主进程在握手后调用，不发起任何网络请求。

import (
	"crypto/tls"
	"fmt"
)

const (
	TLSReasonNoPeerCerts   = "tls-no-peer-certificates"
	TLSReasonVersionLow    = "tls-version-below-floor"
	TLSReasonCipherWeak    = "tls-cipher-suite-weak"
	TLSReasonCipherUnknown = "tls-cipher-suite-unknown"
	TLSReasonNonAEAD       = "tls-non-aead-cipher-in-strict-mode"
	TLSReasonResumedInsecure = "tls-resumed-but-invalid-negotiation"
)

// tlsVersionFloor 支持的最低协议版本（默认 TLS 1.2）。
const tlsVersionFloor = tls.VersionTLS12

// TLSSecurityPolicy 控制协商参数基线。
type TLSSecurityPolicy struct {
	// MinVersion 最低允许版本（0 用默认 TLS1.2）。
	MinVersion uint16
	// RequireAEAD 为 true 时仅允许 AEAD 套件（GCM/ChaCha20），拒绝 CBC。
	RequireAEAD bool
	// AllowUnknownCipher 为 true 时未知套件 id 仅告警不拒绝（保守放行）。
	AllowUnknownCipher bool
}

// DefaultTLSPolicy 默认基线：TLS1.2+、要求 AEAD。
func DefaultTLSPolicy() TLSSecurityPolicy {
	return TLSSecurityPolicy{MinVersion: tlsVersionFloor, RequireAEAD: true}
}

// 弱套件以显式编号列出：crypto/tls 未导出其中少数历史常量（如 0xC008），
// 用编号可完整覆盖 RC4 / 3DES / 匿名族，且不随标准库导出集变化而漏判。
const (
	cipherRSA_RC4_128_SHA         uint16 = 0x0005
	cipherRSA_3DES_EDE_CBC_SHA    uint16 = 0x000A
	cipherECDHE_ECDSA_RC4_128_SHA uint16 = 0xC007
	cipherECDHE_RSA_RC4_128_SHA   uint16 = 0xC011
	cipherECDHE_RSA_3DES_CBC      uint16 = 0xC012
	cipherECDHE_ECDSA_3DES_CBC    uint16 = 0xC008
)

// 明确拒绝的弱套件：RC4、3DES、匿名、空加密/空 MAC、EXPORT。
var tlsWeakCiphers = map[uint16]struct{}{
	cipherRSA_RC4_128_SHA:         {},
	cipherRSA_3DES_EDE_CBC_SHA:    {},
	cipherECDHE_ECDSA_RC4_128_SHA: {},
	cipherECDHE_RSA_RC4_128_SHA:   {},
	cipherECDHE_RSA_3DES_CBC:      {},
	cipherECDHE_ECDSA_3DES_CBC:    {},
}

// 已知的 AEAD 套件白名单（GCM / ChaCha20-Poly1305），覆盖主流实现。
var tlsAEADCiphers = map[uint16]struct{}{
	tls.TLS_AES_128_GCM_SHA256:                {}, // TLS1.3
	tls.TLS_AES_256_GCM_SHA384:                {},
	tls.TLS_CHACHA20_POLY1305_SHA256:          {},
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: {},
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: {},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {},
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    {},
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  {},
}

// 已知的 CBC 套件集合（用于区分“未知”与“已知但非 AEAD”）。
var tlsCBCCiphers = map[uint16]struct{}{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:                {},
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:                {},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:          {},
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:          {},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:        {},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:        {},
}

// TLSEvaluation 是一次连接协商参数的裁决结果。
type TLSEvaluation struct {
	Allowed bool
	Reasons []string
	Version uint16
	Cipher  uint16
}

// EvaluateTLSConnection 校验已协商的连接状态。
func EvaluateTLSConnection(state *tls.ConnectionState, policy TLSSecurityPolicy) TLSEvaluation {
	ev := TLSEvaluation{Allowed: true}
	if policy.MinVersion == 0 {
		policy.MinVersion = tlsVersionFloor
	}
	if state == nil {
		ev.Allowed = false
		ev.Reasons = []string{TLSReasonNoPeerCerts}
		return ev
	}
	ev.Version = state.Version
	ev.Cipher = state.CipherSuite

	if len(state.PeerCertificates) == 0 {
		ev.Allowed = false
		ev.Reasons = append(ev.Reasons, TLSReasonNoPeerCerts)
	}
	if state.Version < policy.MinVersion {
		ev.Allowed = false
		ev.Reasons = append(ev.Reasons, TLSReasonVersionLow)
	}
	if _, weak := tlsWeakCiphers[state.CipherSuite]; weak {
		ev.Allowed = false
		ev.Reasons = append(ev.Reasons, TLSReasonCipherWeak)
	}

	_, isAEAD := tlsAEADCiphers[state.CipherSuite]
	_, isCBC := tlsCBCCiphers[state.CipherSuite]
	// TLS1.3 的套件必然是 AEAD，已在白名单；下面处理 1.2 的判定。
	if policy.RequireAEAD && !isAEAD {
		if isCBC {
			ev.Allowed = false
			ev.Reasons = append(ev.Reasons, TLSReasonNonAEAD)
		} else if !isKnownCipher(state.CipherSuite) && !policy.AllowUnknownCipher {
			ev.Allowed = false
			ev.Reasons = append(ev.Reasons, TLSReasonCipherUnknown)
		}
	}
	return ev
}

func isKnownCipher(id uint16) bool {
	if _, ok := tlsAEADCiphers[id]; ok {
		return true
	}
	if _, ok := tlsCBCCiphers[id]; ok {
		return true
	}
	if _, ok := tlsWeakCiphers[id]; ok {
		return true
	}
	return false
}

// TLSVersionName 返回版本可读名，供日志（不要用字符串推断安全结论，仅展示）。
func TLSVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("TLS-0x%04x", v)
	}
}

// CipherName 包装标准库套件名。
func CipherName(id uint16) string {
	return tls.CipherSuiteName(id)
}
