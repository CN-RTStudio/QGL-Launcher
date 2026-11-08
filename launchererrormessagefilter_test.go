package main

import (
	"strings"
	"testing"
)

func TestSanitizeErrorForUser_Bearer(t *testing.T) {
	in := `failed to call /mojang, got: Bearer abcDEF1234567890XY`
	got := SanitizeErrorForUser(in)
	if strings.Contains(got, "abcDEF1234567890XY") {
		t.Fatalf("bearer not redacted: %s", got)
	}
	if !strings.Contains(got, "<redacted>") {
		t.Fatalf("expected redaction marker: %s", got)
	}
}

func TestSanitizeErrorForUser_TokenKv(t *testing.T) {
	in := `download failed: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def`
	got := SanitizeErrorForUser(in)
	if strings.Contains(got, "eyJhbGci") {
		t.Fatalf("token not redacted: %s", got)
	}
}

func TestSanitizeErrorForUser_WindowsUserPath(t *testing.T) {
	in := `open C:\Users\RealName\AppData\Roaming\.minecraft\options.txt failed`
	got := SanitizeErrorForUser(in)
	if strings.Contains(got, "RealName") {
		t.Fatalf("username not redacted: %s", got)
	}
	if !strings.Contains(got, `<User>`) {
		t.Fatalf("expected <User> placeholder: %s", got)
	}
}

func TestShouldShowToUser_GoroutineHidden(t *testing.T) {
	in := `goroutine 1 [running]: main.foo()
	C:/code/main.go:42 +0x18`
	if ShouldShowToUser(in) {
		t.Fatal("goroutine stack should not be shown to user")
	}
}

func TestShouldShowToUser_NormalShown(t *testing.T) {
	if !ShouldShowToUser("无法连接到服务器 mc.example.com:25565") {
		t.Fatal("normal error should be shown")
	}
}
