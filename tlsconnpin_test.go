package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"
)

func fpOfBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func stateWithSPKI(blobs ...[]byte) *tls.ConnectionState {
	st := &tls.ConnectionState{}
	for _, b := range blobs {
		st.PeerCertificates = append(st.PeerCertificates, &x509.Certificate{RawSubjectPublicKeyInfo: b})
	}
	return st
}

func validPinSet() SPKIPinSet {
	return SPKIPinSet{
		Host:     "api.example.com",
		Primary:  []string{fpOfBytes([]byte("primary-key"))},
		Backup:   []string{fpOfBytes([]byte("backup-key"))},
		NotAfter: time.Now().Add(24 * time.Hour),
	}
}

func TestNormalizeSPKIHex(t *testing.T) {
	if _, ok := NormalizeSPKIHex("abc"); ok {
		t.Fatal("short hex must fail")
	}
	if _, ok := NormalizeSPKIHex("zz00000000000000000000000000000000000000000000000000000000000000"); ok {
		t.Fatal("non-hex must fail")
	}
	in := "AABBCCDDEE"
	_ = in
	good := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if n, ok := NormalizeSPKIHex(good); !ok || n != good {
		t.Fatal("valid 64 hex must normalize")
	}
}

func TestPinSetValidation(t *testing.T) {
	p := validPinSet()
	if _, ok := ValidatePinSet(p); !ok {
		t.Fatal("valid pin set should pass")
	}
	noBackup := p
	noBackup.Backup = nil
	if _, ok := ValidatePinSet(noBackup); ok {
		t.Fatal("missing backup must be invalid")
	}
	noPrimary := p
	noPrimary.Primary = nil
	if _, ok := ValidatePinSet(noPrimary); ok {
		t.Fatal("missing primary must be invalid")
	}
	dup := p
	dup.Backup = []string{p.Primary[0]}
	if _, ok := ValidatePinSet(dup); ok {
		t.Fatal("duplicate primary/backup pin must be invalid")
	}
	badHost := p
	badHost.Host = "  "
	if _, ok := ValidatePinSet(badHost); ok {
		t.Fatal("blank host must be invalid")
	}
}

func TestPinMatchesPrimary(t *testing.T) {
	p := validPinSet()
	st := stateWithSPKI([]byte("primary-key"))
	v := EvaluatePins("api.example.com", st, []SPKIPinSet{p}, time.Now())
	if !v.Allowed || v.Reason != PinReasonMatchedPrimary {
		t.Fatalf("primary should match: %+v", v)
	}
}

func TestPinMatchesBackup(t *testing.T) {
	p := validPinSet()
	st := stateWithSPKI([]byte("backup-key"))
	v := EvaluatePins("api.example.com", st, []SPKIPinSet{p}, time.Now())
	if !v.Allowed || v.Reason != PinReasonMatchedBackup {
		t.Fatalf("backup should match: %+v", v)
	}
}

func TestPinChainMatch(t *testing.T) {
	p := validPinSet()
	// 叶子不匹配，链上第二张匹配备份。
	st := stateWithSPKI([]byte("unknown-leaf"), []byte("backup-key"))
	v := EvaluatePins("api.example.com", st, []SPKIPinSet{p}, time.Now())
	if !v.Allowed || v.Reason != PinReasonMatchedBackup {
		t.Fatalf("chain backup should match: %+v", v)
	}
}

func TestPinNoMatchBlocked(t *testing.T) {
	p := validPinSet()
	st := stateWithSPKI([]byte("attacker-key"))
	v := EvaluatePins("api.example.com", st, []SPKIPinSet{p}, time.Now())
	if v.Allowed || v.Reason != PinReasonNoMatch {
		t.Fatalf("non-matching pin must block: %+v", v)
	}
}

func TestPinNoCertsBlocked(t *testing.T) {
	p := validPinSet()
	v := EvaluatePins("api.example.com", &tls.ConnectionState{}, []SPKIPinSet{p}, time.Now())
	if v.Allowed || v.Reason != PinReasonNoCerts {
		t.Fatalf("missing certs must block: %+v", v)
	}
}

func TestPinNoConfigAllows(t *testing.T) {
	st := stateWithSPKI([]byte("x"))
	v := EvaluatePins("other.example.com", st, []SPKIPinSet{validPinSet()}, time.Now())
	if !v.Allowed || v.Reason != PinReasonNoPin {
		t.Fatalf("unconfigured host should pass: %+v", v)
	}
}

func TestPinWildcardMatching(t *testing.T) {
	if !hostMatchesPin("*.example.com", "a.example.com") {
		t.Fatal("single-label wildcard should match a.example.com")
	}
	if hostMatchesPin("*.example.com", "a.b.example.com") {
		t.Fatal("wildcard must not match multi-label a.b.example.com")
	}
	if hostMatchesPin("*.example.com", "example.com") {
		t.Fatal("wildcard must not match apex")
	}
	if hostMatchesPin("*.example.com", "evil.net") {
		t.Fatal("wildcard must not match unrelated host")
	}
}

func TestPinWildcardEvaluate(t *testing.T) {
	p := validPinSet()
	p.Host = "*.example.com"
	st := stateWithSPKI([]byte("primary-key"))
	v := EvaluatePins("cdn.example.com", st, []SPKIPinSet{p}, time.Now())
	if !v.Allowed {
		t.Fatalf("wildcard host should match: %+v", v)
	}
}

func TestPinExactPreferredOverWildcard(t *testing.T) {
	wild := validPinSet()
	wild.Host = "*.example.com"
	wild.Primary = []string{fpOfBytes([]byte("wild-key"))}
	exact := validPinSet() // host api.example.com, primary primary-key
	st := stateWithSPKI([]byte("primary-key"))
	v := EvaluatePins("api.example.com", st, []SPKIPinSet{wild, exact}, time.Now())
	if !v.Allowed || v.Reason != PinReasonMatchedPrimary {
		t.Fatalf("exact pin set should win: %+v", v)
	}
}

func TestPinExpiredSetMonitorOnly(t *testing.T) {
	p := validPinSet()
	p.NotAfter = time.Now().Add(-time.Hour)
	st := stateWithSPKI([]byte("attacker-key"))
	v := EvaluatePins("api.example.com", st, []SPKIPinSet{p}, time.Now())
	if !v.Allowed || v.Enforced {
		t.Fatalf("expired pin set must not block: %+v", v)
	}
	if v.Reason != PinReasonExpiredNotBlock {
		t.Fatalf("reason=%s", v.Reason)
	}
}

func TestPinReportOnlyMismatchAllowed(t *testing.T) {
	p := validPinSet()
	p.ReportOnly = true
	st := stateWithSPKI([]byte("attacker-key"))
	v := EvaluatePins("api.example.com", st, []SPKIPinSet{p}, time.Now())
	if !v.Allowed || v.Reason != PinReasonReportOnly {
		t.Fatalf("report-only mismatch must be allowed: %+v", v)
	}
}

func TestSPKIFingerprintEmpty(t *testing.T) {
	if SPKIFingerprint(nil) != "" {
		t.Fatal("nil cert fingerprint must be empty")
	}
	if SPKIFingerprint(&x509.Certificate{}) != "" {
		t.Fatal("empty SPKI fingerprint must be empty")
	}
}
