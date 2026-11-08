package main

import (
	"strings"
	"testing"
)

func TestParseProfilesJSONOK(t *testing.T) {
	raw := []byte(`{"profiles":{"test":{"name":"test\r\ninject","lastVersionId":"1.20.4","type":"custom","gameDir":"versions/1.20.4"},"latest":{"name":"Latest","lastVersionId":"1.21","type":"latest-release"}},"selectedUser":{"account":"alice@example.com"},"clientVersion":3}`)
	vd := ParseProfilesJSON(raw, defaultProfileLimits())
	if !vd.OK {
		t.Fatalf("expected ok, got %s", vd.Reason)
	}
	if len(vd.Doc.Profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(vd.Doc.Profiles))
	}
	if strings.Contains(vd.Doc.Profiles[0].Name, "\r") || strings.Contains(vd.Doc.Profiles[0].Name, "\n") {
		t.Fatalf("control chars not stripped: %q", vd.Doc.Profiles[0].Name)
	}
	if vd.Doc.SelectedUser != "alice@example.com" {
		t.Fatalf("selected user wrong: %q", vd.Doc.SelectedUser)
	}
}

func TestParseProfilesJSONOverflow(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"profiles":{`)
	for i := 0; i < 300; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"p` + itoaSafe(i) + `":{"name":"p","lastVersionId":"1.20","type":"custom"}`)
	}
	b.WriteString(`}}`)
	vd := ParseProfilesJSON([]byte(b.String()), defaultProfileLimits())
	if vd.OK || vd.Reason != "profiles-overflow" {
		t.Fatalf("expected profiles-overflow, got ok=%v reason=%s", vd.OK, vd.Reason)
	}
}

func TestParseProfilesJSONDirTraversal(t *testing.T) {
	cases := []string{
		`{"profiles":{"a":{"name":"a","lastVersionId":"1.20","type":"custom","gameDir":"../evil"}}}`,
		`{"profiles":{"a":{"name":"a","lastVersionId":"1.20","type":"custom","gameDir":"C:\\Windows"}}}`,
		`{"profiles":{"a":{"name":"a","lastVersionId":"1.20","type":"custom","gameDir":"/etc"}}}`,
		`{"profiles":{"a":{"name":"a","lastVersionId":"1.20","type":"custom","gameDir":"..\\..\\boot"}}}`,
	}
	for i, c := range cases {
		vd := ParseProfilesJSON([]byte(c), defaultProfileLimits())
		if vd.OK {
			t.Fatalf("case %d: traversal dir accepted", i)
		}
		if vd.Reason != "profile-dir:a" {
			t.Fatalf("case %d: wrong reason %q", i, vd.Reason)
		}
	}
}

func TestParseProfilesJSONBadTypeFallsBack(t *testing.T) {
	raw := []byte(`{"profiles":{"a":{"name":"a","lastVersionId":"1.20","type":"\u001b[31mred","gameDir":"versions/a"}}}`)
	vd := ParseProfilesJSON(raw, defaultProfileLimits())
	if !vd.OK {
		t.Fatalf("expected ok, got %s", vd.Reason)
	}
	if vd.Doc.Profiles[0].Type != "custom" {
		t.Fatalf("expected fallback custom, got %q", vd.Doc.Profiles[0].Type)
	}
}

func TestParseProfilesJSONSizeLimit(t *testing.T) {
	big := `{"profiles":{"a":{"name":"x","lastVersionId":"y","type":"custom"}}}` + strings.Repeat(" ", 5<<20)
	vd := ParseProfilesJSON([]byte(big), defaultProfileLimits())
	if vd.OK || vd.Reason != "json-too-large" {
		t.Fatalf("expected json-too-large, got ok=%v reason=%s", vd.OK, vd.Reason)
	}
}
