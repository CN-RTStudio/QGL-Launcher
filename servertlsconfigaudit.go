package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	tlsReasonOK              = "ok"
	tlsReasonMissing         = "missing"
	tlsReasonUnreadable      = "unreadable"
	tlsReasonSymlink         = "symlink"
	tlsReasonWeakProtocol    = "weak-protocol"
	tlsReasonWeakCipher      = "weak-cipher"
	tlsReasonWorldReadable   = "world-readable-key"
	tlsReasonOutsideDir      = "key-outside-server"
	tlsReasonPlaintextPass   = "plaintext-keystore-password"
	tlsReasonMissingKeystore = "missing-keystore"
	tlsReasonBadKeystore     = "bad-keystore-path"
	tlsReasonTooLarge        = "keystore-too-large"

	tlsMaxKeystoreBytes = 32 << 20
	tlsMaxFindings      = 48
	tlsMaxConfigBytes   = 1 << 20
)

var tlsCfgWeakProtocols = []string{
	"sslv2",
	"sslv3",
	"tlsv1",
	"tlsv1.1",
	"ssl",
}

var tlsCfgWeakCiphers = []string{
	"null",
	"_rc4_",
	"rc4",
	"des_",
	"_des",
	"3des",
	"export",
	"anon",
	"_md5",
	"md5",
	"tls_rsa_with_des",
}

var tlsKeystoreExts = []string{".jks", ".p12", ".pfx", ".keystore"}

type TLSFinding struct {
	Key      string
	Reason   string
	Detail   string
	Blocking bool
}

type TLSAudit struct {
	Dir      string
	Files    []string
	Findings []TLSFinding
}

func (a TLSAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f TLSFinding) bool { return f.Blocking })
}

func (a TLSAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != tlsReasonOK {
			return true
		}
	}
	return false
}

func (a TLSAudit) Describe() string {
	var parts []string
	for _, f := range a.Findings {
		if f.Reason == tlsReasonOK {
			continue
		}
		label := f.Key
		if label == "" {
			label = "tls"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= tlsMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "TLS 配置未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *TLSAudit) add(key, reason, detail string, blocking bool) {
	if len(a.Findings) >= tlsMaxFindings {
		return
	}
	a.Findings = append(a.Findings, TLSFinding{
		Key:      key,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}

func tlsParse(body string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		values[strings.TrimSpace(line[:eq])] = strings.TrimSpace(line[eq+1:])
	}
	return values
}
