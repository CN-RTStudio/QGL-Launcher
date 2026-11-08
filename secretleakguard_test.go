package main

import (
	"strings"
	"testing"
)

func slkHas(fs []SLKFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestSLKAWSAccessKey(t *testing.T) {
	pol := DefaultSLKPolicy()
	safe, fs := SLKInspect("use key AKIAIOSFODNN7EXAMPLE now", pol)
	if safe || !slkHas(fs, SLKReasonAWSAccessKey) {
		t.Fatalf("want aws key, safe=%v fs=%v", safe, fs)
	}
}

func TestSLKGitHubToken(t *testing.T) {
	pol := DefaultSLKPolicy()
	tok := "ghp_" + strings.Repeat("a", 36)
	_, fs := SLKInspect("token="+tok+" done", pol)
	if !slkHas(fs, SLKReasonGitHubToken) {
		t.Fatalf("want github token, got %v", fs)
	}
}

func TestSLKGoogleKey(t *testing.T) {
	pol := DefaultSLKPolicy()
	key := "AIza" + strings.Repeat("Z", 35) // 4+35 = 39
	_, fs := SLKInspect("k=" + key, pol)
	if !slkHas(fs, SLKReasonGoogleAPIKey) {
		t.Fatalf("want google key, got %v", fs)
	}
}

func TestSLKStripeLive(t *testing.T) {
	pol := DefaultSLKPolicy()
	_, fs := SLKInspect("sk_live_" + strings.Repeat("x", 30), pol)
	if !slkHas(fs, SLKReasonStripeLiveKey) {
		t.Fatalf("want stripe key, got %v", fs)
	}
}

func TestSLKSlack(t *testing.T) {
	pol := DefaultSLKPolicy()
	_, fs := SLKInspect("xoxb-1234567890-abcdef", pol)
	if !slkHas(fs, SLKReasonSlackToken) {
		t.Fatalf("want slack token, got %v", fs)
	}
}

func TestSLKPrivateKeyPEM(t *testing.T) {
	pol := DefaultSLKPolicy()
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"
	_, fs := SLKInspect("loaded\n" + pem + "\nend", pol)
	if !slkHas(fs, SLKReasonPrivateKeyPEM) {
		t.Fatalf("want pem key, got %v", fs)
	}
}

func TestSLKJWT(t *testing.T) {
	pol := DefaultSLKPolicy()
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	_, fs := SLKInspect("Bearer " + jwt, pol)
	if !slkHas(fs, SLKReasonJWT) {
		t.Fatalf("want jwt, got %v", fs)
	}
}

func TestSLKBearerHeader(t *testing.T) {
	pol := DefaultSLKPolicy()
	pol.DetectHighEntropy = false
	_, fs := SLKInspect("Authorization: Bearer abc123secretvalue", pol)
	if !slkHas(fs, SLKReasonBearerHeader) {
		t.Fatalf("want bearer, got %v", fs)
	}
}

func TestSLKPasswordAssignment(t *testing.T) {
	pol := DefaultSLKPolicy()
	pol.DetectHighEntropy = false
	_, fs := SLKInspect("proxy password=hunter2hunter2 ok", pol)
	if !slkHas(fs, SLKReasonAssignment) {
		t.Fatalf("want assignment, got %v", fs)
	}
}

func TestSLKCleanText(t *testing.T) {
	pol := DefaultSLKPolicy()
	pol.DetectHighEntropy = false
	safe, _ := SLKInspect("Server started on port 25565, player joined", pol)
	if !safe {
		t.Fatal("ordinary text should be safe")
	}
}

func TestSLKRedact(t *testing.T) {
	pol := DefaultSLKPolicy()
	tok := "ghp_" + strings.Repeat("b", 36)
	text := "x " + tok + " y"
	_, fs := SLKInspect(text, pol)
	out := SLKRedact(text, fs, pol)
	if strings.Contains(out, strings.Repeat("b", 20)) {
		t.Fatal("token not masked")
	}
	if !strings.HasPrefix(out, "x ghp_") {
		t.Fatal("prefix hint should be retained")
	}
}

func TestSLKRedactNoFindings(t *testing.T) {
	pol := DefaultSLKPolicy()
	in := "nothing here"
	if SLKRedact(in, nil, pol) != in {
		t.Fatal("should return unchanged")
	}
}

func TestSLKDistinct(t *testing.T) {
	if slkDistinct("aabbcc") != 3 {
		t.Fatal("distinct count wrong")
	}
}
