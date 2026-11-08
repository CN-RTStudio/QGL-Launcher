package main

import (
	"strings"
	"testing"
)

func TestTokenizeCommandLineBasic(t *testing.T) {
	argv, balanced := tokenizeCommandLine(`C:\jdk\bin\java.exe -Xmx2G -jar server.jar nogui`)
	if !balanced {
		t.Fatal("正常命令行引号应配平")
	}
	want := []string{`C:\jdk\bin\java.exe`, "-Xmx2G", "-jar", "server.jar", "nogui"}
	if !equalStrings(argv, want) {
		t.Fatalf("分词不符:\n got=%v\nwant=%v", argv, want)
	}
}

func TestTokenizeCommandLineQuotedSpaces(t *testing.T) {
	argv, balanced := tokenizeCommandLine(`"C:\Program Files\jdk\bin\java.exe" "-Dp=a b" -jar x.jar`)
	if !balanced {
		t.Fatal("引号应配平")
	}
	if len(argv) != 4 {
		t.Fatalf("参数数不对: %v", argv)
	}
	if argv[0] != `C:\Program Files\jdk\bin\java.exe` {
		t.Fatalf("带空格程序名分词错误: %q", argv[0])
	}
	if argv[1] != `-Dp=a b` {
		t.Fatalf("引用态空格不应分词: %q", argv[1])
	}
}

func TestTokenizeCommandLineEscapedQuote(t *testing.T) {
	// 奇数反斜杠 + 引号 => 字面引号且不切换引用态。
	argv, balanced := tokenizeCommandLine(`java.exe -Dmsg=say\"hello world\" x`)
	if !balanced {
		t.Fatal("被转义的引号不应导致配平失败")
	}
	found := false
	for _, a := range argv {
		if strings.Contains(a, `"hello`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("字面引号未保留: %v", argv)
	}
}

func TestTokenizeCommandLineUnbalanced(t *testing.T) {
	if _, balanced := tokenizeCommandLine(`java.exe -Dp="oops -jar x.jar`); balanced {
		t.Fatal("奇数个结构性引号必须判定为不配平")
	}
}

func TestAuditCommandLineRejectsInjection(t *testing.T) {
	bad := []string{
		"",
		"   \t ",
		"java.exe -Xmx2G\r\ncalc.exe",
		"java.exe -Dp=x\n-y",
		"java.exe\x00evil",
		strings.Repeat("a", maxCommandLineBytes+1),
		`java.exe -Dp="unbalanced`,
	}
	for _, in := range bad {
		_, audit := AuditCommandLine(in, false)
		if !audit.HasCritical() {
			t.Fatalf("应判定为 critical: %q", truncateForLog(in))
		}
	}
}

func TestAuditCommandLineRejectsArgOverflow(t *testing.T) {
	var b strings.Builder
	b.WriteString("java.exe")
	for i := 0; i < maxLaunchArgs+5; i++ {
		b.WriteString(" -Dp")
		b.WriteString(itoaForTest(i))
	}
	_, audit := AuditCommandLine(b.String(), false)
	if !auditHasCode(audit, "cmdline-too-many-args") {
		t.Fatalf("参数数超限应命中 cmdline-too-many-args, codes=%v", audit.Findings)
	}
}

func TestAuditCommandLineRejectsLongArg(t *testing.T) {
	long := strings.Repeat("x", maxLaunchArgBytes+1)
	_, audit := AuditCommandLine("java.exe -Dp="+long, false)
	if !auditHasCode(audit, "cmdline-arg-long") {
		t.Fatal("超长单参应命中 cmdline-arg-long")
	}
}

func TestAuditCommandLineChecksArgv0(t *testing.T) {
	// argv[0] 合法：放行。
	good := javaExeForTest() + " -Xmx2G -jar a.jar nogui"
	if _, audit := AuditCommandLine(good, true); audit.HasCritical() {
		t.Fatalf("合法 java 命令行应放行，首个 code=%s", audit.FirstCriticalCode())
	}
	// argv[0] 为 UNC / 相对 / 穿越路径：拒绝。
	bad := []string{
		`\\host\share\java.exe -jar a.jar`,
		`java -jar a.jar`,
		`C:\app\..\evil\java.exe -jar a.jar`,
	}
	for _, in := range bad {
		_, audit := AuditCommandLine(in, true)
		if !audit.HasCritical() {
			t.Fatalf("危险 argv0 应拒绝: %q", in)
		}
	}
}

func TestAuditCommandLineNoArgv0CheckWhenNotRequired(t *testing.T) {
	// 非 java 场景（如只审一条普通命令行）不应套用 java 扩展名/绝对路径规则。
	_, audit := AuditCommandLine("some-tool --flag value", false)
	if audit.HasCritical() {
		t.Fatalf("不要求校验 argv0 时不应因程序名形态拒绝: %v", audit.Findings)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func auditHasCode(a *LaunchAudit, code string) bool {
	for _, f := range a.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func truncateForLog(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

func itoaForTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
