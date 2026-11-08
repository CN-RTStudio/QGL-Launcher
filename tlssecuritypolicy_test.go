package main

import (
	"crypto/tls"
	"testing"
)

func stateWith(version, cipher uint16, certs int) *tls.ConnectionState {
	st := &tls.ConnectionState{Version: version, CipherSuite: cipher}
	for i := 0; i < certs; i++ {
		st.PeerCertificates = append(st.PeerCertificates, nil)
	}
	return st
}

func TestTLSPolicyAllowsModern(t *testing.T) {
	pol := DefaultTLSPolicy()
	st := stateWith(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, 1)
	ev := EvaluateTLSConnection(st, pol)
	if !ev.Allowed {
		t.Fatalf("TLS1.3 AEAD must pass, reasons=%v", ev.Reasons)
	}
}

func TestTLSPolicyAllowsTLS12AEAD(t *testing.T) {
	pol := DefaultTLSPolicy()
	st := stateWith(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, 1)
	ev := EvaluateTLSConnection(st, pol)
	if !ev.Allowed {
		t.Fatalf("TLS1.2 ChaCha20 must pass, reasons=%v", ev.Reasons)
	}
}

func TestTLSPolicyRejectsTLS11(t *testing.T) {
	pol := DefaultTLSPolicy()
	st := stateWith(tls.VersionTLS11, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 1)
	ev := EvaluateTLSConnection(st, pol)
	if ev.Allowed || !tlsContainsReason(ev.Reasons, TLSReasonVersionLow) {
		t.Fatalf("TLS1.1 must be rejected: %+v", ev)
	}
}

func TestTLSPolicyRejects3DES(t *testing.T) {
	pol := DefaultTLSPolicy()
	st := stateWith(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 1)
	ev := EvaluateTLSConnection(st, pol)
	if ev.Allowed || !tlsContainsReason(ev.Reasons, TLSReasonCipherWeak) {
		t.Fatalf("3DES must be rejected: %+v", ev)
	}
}

func TestTLSPolicyRejectsCBCInStrictMode(t *testing.T) {
	pol := DefaultTLSPolicy()
	st := stateWith(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 1)
	ev := EvaluateTLSConnection(st, pol)
	if ev.Allowed || !tlsContainsReason(ev.Reasons, TLSReasonNonAEAD) {
		t.Fatalf("CBC must be rejected when AEAD required: %+v", ev)
	}
}

func TestTLSPolicyAllowsCBCWhenAEADDisabled(t *testing.T) {
	pol := DefaultTLSPolicy()
	pol.RequireAEAD = false
	st := stateWith(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 1)
	ev := EvaluateTLSConnection(st, pol)
	if !ev.Allowed {
		t.Fatalf("CBC should pass with relaxed policy: %+v", ev.Reasons)
	}
}

func TestTLSPolicyRejectsUnknownCipherByDefault(t *testing.T) {
	pol := DefaultTLSPolicy()
	st := stateWith(tls.VersionTLS12, 0xFFFF, 1)
	ev := EvaluateTLSConnection(st, pol)
	if ev.Allowed || !tlsContainsReason(ev.Reasons, TLSReasonCipherUnknown) {
		t.Fatalf("unknown cipher must be rejected: %+v", ev)
	}
}

func TestTLSPolicyUnknownCipherWarnOnlyWhenAllowed(t *testing.T) {
	pol := DefaultTLSPolicy()
	pol.AllowUnknownCipher = true
	st := stateWith(tls.VersionTLS12, 0xFFFF, 1)
	ev := EvaluateTLSConnection(st, pol)
	if !ev.Allowed {
		t.Fatalf("unknown cipher should pass with AllowUnknownCipher: %+v", ev.Reasons)
	}
}

func TestTLSPolicyRejectsNoPeerCerts(t *testing.T) {
	pol := DefaultTLSPolicy()
	ev := EvaluateTLSConnection(stateWith(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, 0), pol)
	if ev.Allowed || !tlsContainsReason(ev.Reasons, TLSReasonNoPeerCerts) {
		t.Fatalf("missing peer certs must be rejected: %+v", ev)
	}
}

func TestTLSPolicyNilState(t *testing.T) {
	ev := EvaluateTLSConnection(nil, DefaultTLSPolicy())
	if ev.Allowed {
		t.Fatal("nil state must be rejected")
	}
}

func TestTLSVersionNameHelper(t *testing.T) {
	if TLSVersionName(tls.VersionTLS12) != "TLS1.2" {
		t.Fatal("version name mismatch")
	}
	if CipherName(tls.TLS_AES_128_GCM_SHA256) == "" {
		t.Fatal("cipher name must not be empty")
	}
}

func tlsContainsReason(rs []string, want string) bool {
	for _, r := range rs {
		if r == want {
			return true
		}
	}
	return false
}
