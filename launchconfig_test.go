package main

import (
	"strings"
	"testing"
)

func TestLaunchConfigValidateArgs(t *testing.T) {
	lim := defaultLaunchLimits()
	good := []string{
		"-Xmx2G", "-jar", "versions/1.20.1/1.20.1.jar", "--username", "Steve",
		"--version", "1.20.1", "--gameDir", "instances/world1",
	}
	vd := ValidateLaunchConfig(good, "instances/world1", "assets", lim)
	if !vd.OK {
		t.Fatalf("good rejected: %s", vd.Reason)
	}

	bad := []struct {
		name string
		argv []string
		want string
	}{
		{"argfile", []string{"-jar", "x.jar", "@evil.args"}, "argfile"},
		{"jar-reentry", []string{"-jar", "a.jar", "-jar", "b.jar"}, "jar-reentry"},
		{"nul", []string{"-jar", "a.jar", "-X\x00mx"}, "nul"},
		{"banned-launcher", []string{"--launcher", "x"}, "banned-flag"},
		{"banned-demo", []string{"--demo"}, "banned-flag"},
		{"version-illegal", []string{"-jar", "a.jar", "-version", "../../evil"}, "version-illegal-value"},
		{"cp-after-jar", []string{"-jar", "a.jar", "-cp", "x"}, "cp-after-jar"},
		{"empty-arg", []string{"-jar", ""}, "empty-arg"},
	}
	for _, c := range bad {
		vd := ValidateLaunchConfig(c.argv, "", "", lim)
		if vd.OK || !strings.Contains(vd.Reason, c.want) {
			t.Fatalf("%s: ok=%v reason=%q want %q", c.name, vd.OK, vd.Reason, c.want)
		}
	}
}

func TestLaunchConfigDirAndUser(t *testing.T) {
	lim := defaultLaunchLimits()
	vd := ValidateLaunchConfig([]string{"-jar", "a.jar"}, "../escape", "", lim)
	if vd.OK || vd.Reason != "dir:dotdot" {
		t.Fatalf("dotdot dir accepted: %v", vd.Reason)
	}
	vd = ValidateLaunchConfig([]string{"-jar", "a.jar"}, "", "assets", lim)
	if !vd.OK {
		t.Fatalf("assets dir rejected: %s", vd.Reason)
	}
	if r := ValidateUsername("Steve_42", lim); r != "" {
		t.Fatalf("good username rejected: %s", r)
	}
	for _, c := range []struct{ in, want string }{
		{"", "empty"},
		{"a/b", "illegal-char"},
		{"sp ace", "illegal-char"},
		{strings.Repeat("x", 40), "too-long"},
		{"x\x01y", "control-char"},
	} {
		if r := ValidateUsername(c.in, lim); r != c.want {
			t.Fatalf("%q: got %q want %q", c.in, r, c.want)
		}
	}
}

func TestLaunchConfigVersionValue(t *testing.T) {
	lim := defaultLaunchLimits()
	for _, v := range []string{"1.20.1", "1.8", "1.8+", "47.1.0", "1.20.4-beta"} {
		// beta 形态不允许（非纯数字点号）
		if v == "1.20.4-beta" && versionValueOK(v, lim) {
			t.Fatalf("beta accepted: %s", v)
		}
		if v != "1.20.4-beta" && !versionValueOK(v, lim) {
			t.Fatalf("version rejected: %s", v)
		}
	}
	for _, v := range []string{"../evil", "-jar", "a;b", "x y", ".."} {
		if versionValueOK(v, lim) {
			t.Fatalf("illegal version accepted: %s", v)
		}
	}
}

func TestSummarizeLaunchVerdict(t *testing.T) {
	if s := SummarizeLaunchVerdict(launchVerdict{OK: true, Argv: []string{"a", "b"}}); s != "launch ok args=2" {
		t.Fatalf("summary wrong: %q", s)
	}
	if s := SummarizeLaunchVerdict(launchVerdict{OK: false, Reason: "argfile"}); s != "launch bad argfile" {
		t.Fatalf("summary wrong: %q", s)
	}
}
