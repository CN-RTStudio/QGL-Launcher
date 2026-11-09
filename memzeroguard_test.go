package main

import "testing"

func mzgHas(fs []MZGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestMZGClean(t *testing.T) {
	tr := NewMemZeroTracker()
	buf := []byte("hunter2hunter2")
	tr.Register("pw", "password", len(buf))
	ZeroizeBytes(buf)
	if string(buf) != "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" {
		t.Fatal("buffer should be wiped")
	}
	tr.ZeroizeBuffer("pw")
	safe, _ := tr.Audit()
	if !safe {
		t.Fatal("zeroized scoped buffer should pass")
	}
}

func TestMZGNotZeroized(t *testing.T) {
	tr := NewMemZeroTracker()
	tr.Register("rt", "refresh-token", 32)
	_, fs := tr.Audit()
	if !mzgHas(fs, MZGReasonBufferNotZeroized) {
		t.Fatalf("want not zeroized, got %v", fs)
	}
}

func TestMZGImmutableString(t *testing.T) {
	tr := NewMemZeroTracker()
	tr.Register("pw", "password", 14)
	tr.MarkImmutableCopy("pw")
	tr.ZeroizeBuffer("pw")
	_, fs := tr.Audit()
	if !mzgHas(fs, MZGReasonImmutableStringCopy) {
		t.Fatalf("want immutable copy, got %v", fs)
	}
}

func TestMZGLongLivedRetention(t *testing.T) {
	tr := NewMemZeroTracker()
	tr.Register("at", "access-token", 40)
	tr.MarkRetention("at")
	_, fs := tr.Audit()
	if !mzgHas(fs, MZGReasonTokenInLongLived) {
		t.Fatalf("want long lived retention, got %v", fs)
	}
}

func TestMZGZeroizedAfterRetention(t *testing.T) {
	tr := NewMemZeroTracker()
	tr.Register("rt", "refresh-token", 40)
	tr.MarkRetention("rt")
	tr.ZeroizeBuffer("rt")
	_, fs := tr.Audit()
	if !mzgHas(fs, MZGReasonZeroizedTooLate) {
		t.Fatalf("want zeroized too late, got %v", fs)
	}
}

func TestMZGDoubleZeroize(t *testing.T) {
	tr := NewMemZeroTracker()
	tr.Register("pw", "password", 8)
	if !tr.ZeroizeBuffer("pw") {
		t.Fatal("first zeroize should report true")
	}
	if tr.ZeroizeBuffer("pw") {
		t.Fatal("second zeroize should report false")
	}
}

func TestMZGUnknownBuffer(t *testing.T) {
	tr := NewMemZeroTracker()
	if tr.ZeroizeBuffer("nope") {
		t.Fatal("unknown buffer zeroize should be false")
	}
}

func TestMZGRegisterIdempotent(t *testing.T) {
	tr := NewMemZeroTracker()
	tr.Register("x", "password", 1)
	tr.Register("x", "password", 99)
	tr.ZeroizeBuffer("x")
	safe, fs := tr.Audit()
	if !safe || len(fs) != 0 {
		t.Fatalf("duplicate register must not create a second entry, got %v", fs)
	}
}

func TestMZGTokenInURL(t *testing.T) {
	tok := "abc.def.secret"
	_, fs := MZGInspectTokenUsage(tok, "https://api.test/x?access_token="+tok)
	if !mzgHas(fs, MZGReasonTokenInURL) {
		t.Fatalf("want token in url, got %v", fs)
	}
}

func TestMZGTokenNotInURL(t *testing.T) {
	safe, fs := MZGInspectTokenUsage("secrettoken", "https://api.test/profile")
	if !safe || len(fs) != 0 {
		t.Fatalf("unrelated url should be safe, got %v", fs)
	}
}
