package main

import (
	"strings"
	"testing"
)

func TestCDSimpleQuoted(t *testing.T) {
	r, err := ParseContentDisposition(`attachment; filename="mod.jar"`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Disposition != "attachment" || r.Filename != "mod.jar" {
		t.Fatalf("parse wrong: %+v", r)
	}
	if n := r.PreferredFilename(); n != "mod.jar" {
		t.Fatalf("preferred=%s", n)
	}
}

func TestCDTokenValue(t *testing.T) {
	r, err := ParseContentDisposition(`attachment; filename=mod-1.2.3.jar`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Filename != "mod-1.2.3.jar" {
		t.Fatalf("token filename=%s", r.Filename)
	}
}

func TestCDFilenameStarPreferred(t *testing.T) {
	r, err := ParseContentDisposition(`attachment; filename="fallback.bin"; filename*=UTF-8''real.jar`)
	if err != nil {
		t.Fatal(err)
	}
	if r.PreferredFilename() != "real.jar" {
		t.Fatalf("filename* must win, got %s", r.PreferredFilename())
	}
}

func TestCDFilenameStarPercentUTF8(t *testing.T) {
	// %E4%B8%AD = U+4E2D（中）
	name, err := ResolveDownloadFilename(`attachment; filename*=UTF-8''%E4%B8%AD.jar`)
	if err != nil {
		t.Fatal(err)
	}
	if name != "中.jar" {
		t.Fatalf("decoded=%q", name)
	}
}

func TestCDInlineDisposition(t *testing.T) {
	r, err := ParseContentDisposition(`inline; filename="p.png"`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Disposition != "inline" {
		t.Fatalf("disposition=%s", r.Disposition)
	}
}

func TestCDExtraParams(t *testing.T) {
	r, err := ParseContentDisposition(`attachment; filename="a"; size=123; creation-date="x"`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Params["size"] != "123" {
		t.Fatalf("params=%+v", r.Params)
	}
}

func TestCDRejectPathTraversal(t *testing.T) {
	_, err := ResolveDownloadFilename(`attachment; filename="../../etc/passwd"`)
	if CDReason(err) != CDReasonPathSeparator {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectTraversalInStar(t *testing.T) {
	_, err := ResolveDownloadFilename(`attachment; filename*=UTF-8''..%2F..%2Fx.jar`)
	if CDReason(err) != CDReasonPathSeparator {
		t.Fatalf("encoded slash must be caught after decode, reason=%s", CDReason(err))
	}
}

func TestCDRejectDrive(t *testing.T) {
	_, err := ResolveDownloadFilename(`attachment; filename="C:evil.jar"`)
	if CDReason(err) != CDReasonDriveOrUNC {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectReservedDevice(t *testing.T) {
	_, err := ResolveDownloadFilename(`attachment; filename="CON.jar"`)
	if CDReason(err) != CDReasonReservedDevice {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectLeadingDot(t *testing.T) {
	_, err := ResolveDownloadFilename(`attachment; filename=".bashrc"`)
	if CDReason(err) != CDReasonLeadingDotSpace {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectDotsOnly(t *testing.T) {
	_, err := ResolveDownloadFilename(`attachment; filename="..."`)
	if CDReason(err) != CDReasonDotOrSpace {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectBadCharset(t *testing.T) {
	_, err := ParseContentDisposition(`attachment; filename*=ISO-8859-1''caf%E9.jar`)
	if CDReason(err) != CDReasonUnsafeCharset {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectBadPercent(t *testing.T) {
	_, err := ParseContentDisposition(`attachment; filename*=UTF-8''a%zz.jar`)
	if CDReason(err) != CDReasonBadPercent {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectInvalidUTF8(t *testing.T) {
	// %FF 单独不是合法 UTF-8 起始字节。
	_, err := ParseContentDisposition(`attachment; filename*=UTF-8''a%FF.jar`)
	if CDReason(err) != CDReasonBadPercent {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDEmptyHeader(t *testing.T) {
	if _, err := ParseContentDisposition("   "); CDReason(err) != CDReasonEmpty {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDMalformedParam(t *testing.T) {
	// 缺少 '='
	if _, err := ParseContentDisposition(`attachment; filename`); CDReason(err) != CDReasonMalformed {
		t.Fatalf("missing = reason=%s", CDReason(err))
	}
	// 未闭合引号
	if _, err := ParseContentDisposition(`attachment; filename="abc`); CDReason(err) != CDReasonMalformed {
		t.Fatalf("unclosed quote reason=%s", CDReason(err))
	}
}

func TestCDNoFilename(t *testing.T) {
	if _, err := ResolveDownloadFilename(`attachment; size=10`); CDReason(err) != CDReasonNoFilename {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDQuotedPair(t *testing.T) {
	r, err := ParseContentDisposition(`attachment; filename="a\"b.jar"`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Filename != `a"b.jar` {
		t.Fatalf("quoted-pair decoded=%q", r.Filename)
	}
}

func TestCDTooLongHeader(t *testing.T) {
	big := "attachment; filename=" + string(make([]byte, 9000))
	_, err := ParseContentDisposition(big)
	if CDReason(err) != CDReasonMalformed {
		t.Fatalf("oversize header reason=%s", CDReason(err))
	}
}

func TestCDReasonHelper(t *testing.T) {
	if CDReason(nil) != "" {
		t.Fatal("nil error reason must be empty")
	}
	if DescribeCDReason(CDReasonControlChar) == "" {
		t.Fatal("description must not be empty")
	}
}

// urlPercentForTest 把任意字符串按字节百分号编码，供 filename* 用例构造输入。
func urlPercentForTest(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteString(strings.ToUpper(hex2(c)))
	}
	return b.String()
}

func hex2(c byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[c>>4], digits[c&0x0f]})
}

func TestCDRejectAlternateDataStream(t *testing.T) {
	for _, hdr := range []string{
		`attachment; filename="invoice.pdf:hidden.exe"`,
		`attachment; filename="a.jar:payload"`,
	} {
		_, err := ResolveDownloadFilename(hdr)
		if CDReason(err) != CDReasonAlternateStream {
			t.Fatalf("%s reason=%s", hdr, CDReason(err))
		}
	}
}

func TestCDRejectForbiddenWindowsChars(t *testing.T) {
	for _, name := range []string{"a<b.jar", "a>b.jar", "a|b.jar", "a?b.jar", "a*b.jar", `a"b.jar`} {
		_, err := ResolveDownloadFilename(`attachment; filename*=UTF-8''` + urlPercentForTest(name))
		if CDReason(err) != CDReasonForbiddenChar {
			t.Fatalf("%q reason=%s", name, CDReason(err))
		}
	}
}

func TestCDRejectInvisibleRunes(t *testing.T) {
	cases := []string{
		"evil\u202eexe.jar",
		"ev\u200bile.jar",
		"a\ufeffb.jar",
	}
	for _, name := range cases {
		_, err := ResolveDownloadFilename(`attachment; filename*=UTF-8''` + urlPercentForTest(name))
		if CDReason(err) != CDReasonInvisibleRune {
			t.Fatalf("%q reason=%s", name, CDReason(err))
		}
	}
}

func TestCDRejectDuplicateFilenameParams(t *testing.T) {
	cases := []string{
		`attachment; filename="a.jar"; filename="b.jar"`,
		`attachment; filename*=UTF-8''a.jar; filename*=UTF-8''b.jar`,
	}
	for _, hdr := range cases {
		_, err := ParseContentDisposition(hdr)
		if CDReason(err) != CDReasonDuplicateParam {
			t.Fatalf("%s reason=%s", hdr, CDReason(err))
		}
	}
}

func TestCDRejectBareControlInQuoted(t *testing.T) {
	cases := []string{
		"attachment; filename=\"a\x01b.jar\"",
		"attachment; filename=\"a\x7fb.jar\"",
		"attachment; filename=\"a\x00b.jar\"",
	}
	for _, hdr := range cases {
		if _, err := ParseContentDisposition(hdr); CDReason(err) != CDReasonMalformed {
			t.Fatalf("控制字符必须按畸形拒绝: %q reason=%s", hdr, CDReason(err))
		}
	}
	if _, err := ParseContentDisposition("attachment; filename=\"a\tb.jar\""); err != nil {
		t.Fatalf("HTAB 是 RFC 允许的 quoted-string 字符: %v", err)
	}
}

func TestCDResolveValidName(t *testing.T) {
	name, err := ResolveDownloadFilename(`attachment; filename="OptiFine_1.20.1.jar"`)
	if err != nil {
		t.Fatal(err)
	}
	if name != "OptiFine_1.20.1.jar" {
		t.Fatalf("name=%q", name)
	}
}
