package main

import (
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

func tlsCfgWeakProtocol(value string) string {
	lower := strings.ToLower(value)
	for _, weak := range tlsCfgWeakProtocols {
		if strings.Contains(lower, weak) {
			return weak
		}
	}
	return ""
}
func tlsCfgWeakCipher(value string) string {
	lower := strings.ToLower(value)
	for _, weak := range tlsCfgWeakCiphers {
		if strings.Contains(lower, weak) {
			return weak
		}
	}
	return ""
}
func tlsIsKeystore(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range tlsKeystoreExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
