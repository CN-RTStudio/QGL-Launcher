package main

import "testing"

func TestParseMinecraftVersionReleases(t *testing.T) {
	cases := []struct {
		in    string
		maj   int
		min   int
		patch int
		kind  string
	}{
		{"1", 1, 0, 0, mcVersionRelease},
		{"1.20", 1, 20, 0, mcVersionRelease},
		{"1.20.4", 1, 20, 4, mcVersionRelease},
		{"1.21", 1, 21, 0, mcVersionRelease},
		{"1.7.10", 1, 7, 10, mcVersionRelease},
	}
	for _, c := range cases {
		v, ok := ParseMinecraftVersion(c.in)
		if !ok || v.Kind != c.kind || v.Major != c.maj || v.Minor != c.min || v.Patch != c.patch {
			t.Fatalf("ParseMinecraftVersion(%q)=%+v ok=%v want %d.%d.%d %s", c.in, v, ok, c.maj, c.min, c.patch, c.kind)
		}
	}
}

func TestParseMinecraftVersionSnapshots(t *testing.T) {
	v, ok := ParseMinecraftVersion("24w14a")
	if !ok || v.Kind != mcVersionSnapshot || v.SnapYear != 24 || v.SnapWeek != 14 {
		t.Fatalf("snapshot parse wrong: %+v ok=%v", v, ok)
	}
	if _, ok := ParseMinecraftVersion("24w54a"); ok {
		t.Fatal("week 54 should be rejected")
	}
	if _, ok := ParseMinecraftVersion("24w00a"); ok {
		t.Fatal("week 0 should be rejected")
	}
}

func TestParseMinecraftVersionPrerelease(t *testing.T) {
	v, ok := ParseMinecraftVersion("1.21-pre1")
	if !ok || v.Kind != mcVersionPrerelease || v.Minor != 21 || v.PreSeq != 1 {
		t.Fatalf("pre parse wrong: %+v ok=%v", v, ok)
	}
	v2, ok := ParseMinecraftVersion("1.21-rc2")
	if !ok || v2.Kind != mcVersionPrerelease || v2.PreSeq != 2 {
		t.Fatalf("rc parse wrong: %+v ok=%v", v2, ok)
	}
}

func TestParseMinecraftVersionRejects(t *testing.T) {
	bad := []string{
		"", "1.abc", "1.20.x", "abc.1", "1.2.3.4",
		"01.20.1", "1.02.3", "1..5", "-1.2", "1.-2",
		"1000.0.0", "1.20.1000", "999999999999.0",
		"1.20.1-forge-47.2.0", // 加载器后缀不在纯版本函数放行范围
		"1.20 ", " 1.20", "1.20\n", "javascript:x",
	}
	for _, b := range bad {
		if v, ok := ParseMinecraftVersion(b); ok {
			t.Fatalf("ParseMinecraftVersion(%q) should be rejected, got %+v", b, v)
		}
	}
}

func TestStripLoaderSuffix(t *testing.T) {
	cases := map[string]string{
		"1.20.1-forge-47.2.0": "1.20.1",
		"1.21 fabric":         "1.21",
		"1.19.2":              "1.19.2",
	}
	for in, want := range cases {
		if got := stripLoaderSuffix(in); got != want {
			t.Fatalf("stripLoaderSuffix(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCompareRelease(t *testing.T) {
	a, _ := ParseMinecraftVersion("1.20.5")
	b, _ := ParseMinecraftVersion("1.20.4")
	c, _ := ParseMinecraftVersion("1.21")
	d, _ := ParseMinecraftVersion("1.20.5")
	if CompareRelease(a, b) <= 0 {
		t.Fatal("1.20.5 should be > 1.20.4")
	}
	if CompareRelease(a, c) >= 0 {
		t.Fatal("1.20.5 should be < 1.21")
	}
	if CompareRelease(a, d) != 0 {
		t.Fatal("1.20.5 should equal 1.20.5")
	}
}

func TestAtLeast(t *testing.T) {
	v, _ := ParseMinecraftVersion("1.20.5")
	if !v.AtLeast(1, 20, 5) {
		t.Fatal("1.20.5 >= 1.20.5")
	}
	if !v.AtLeast(1, 18, 0) {
		t.Fatal("1.20.5 >= 1.18")
	}
	if v.AtLeast(1, 21, 0) {
		t.Fatal("1.20.5 should not be >= 1.21")
	}
	snap, _ := ParseMinecraftVersion("24w14a")
	if snap.AtLeast(1, 0, 0) {
		t.Fatal("snapshot should not participate in release comparison")
	}
	pre, _ := ParseMinecraftVersion("1.21-pre1")
	if !pre.AtLeast(1, 21, 0) {
		t.Fatal("1.21-pre1 core should compare as 1.21")
	}
}

func TestValidSegment(t *testing.T) {
	good := map[string]int{"0": 0, "1": 1, "17": 17, "999": 999}
	for s, want := range good {
		n, ok := validSegment(s)
		if !ok || n != want {
			t.Fatalf("validSegment(%q)=%d,%v want %d", s, n, ok, want)
		}
	}
	for _, s := range []string{"", "00", "01", "1000", "1a", "-1", "9999"} {
		if _, ok := validSegment(s); ok {
			t.Fatalf("validSegment(%q) should fail", s)
		}
	}
}

func TestSignInt(t *testing.T) {
	if signInt(-500) != -1 || signInt(0) != 0 || signInt(9) != 1 {
		t.Fatal("signInt normalization wrong")
	}
}
