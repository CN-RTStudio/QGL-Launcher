package main

import (
	"strings"
	"testing"
)

func TestIsSystemDirEntry(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{`C:\Windows`, true},
		{`c:\windows`, true},
		{`C:\Windows\System32`, true},
		{`C:\Windows\System32\WindowsPowerShell\v1.0`, true},
		{`C:\Windows\SysWOW64`, true},
		{`C:\Windows\SysWOW64\wbem`, true},
		{`D:\Windows\System32`, true},
		{`C:\Users\joe\Downloads`, false},
		{`C:\Temp`, false},
		{`C:\ProgramData`, false},
		{`C:\`, false},
		{`C:\Windows\Temp`, false},
		{`relative\path`, false},
		{`C:\Program Files\Java\bin`, false},
		{`\\server\share\evil`, false},
		{`C:\Windows\Fonts`, false}, // 系统字体目录不含 System32/SysWOW64 段
		{``, false},
		{`"C:\Windows\System32"`, true}, // 带引号条目
	}
	for _, c := range cases {
		if got := isSystemDirEntry(c.in); got != c.want {
			t.Fatalf("isSystemDirEntry(%q)=%v, want %v", c.in, got, c.want)
		}
	}
}

func TestSafePathList(t *testing.T) {
	entries := []string{
		`C:\Windows\System32`,
		`C:\Windows`,
		`C:\Users\joe\Downloads`,
		`C:\Temp`,
		`D:\Games\evil`,
		`C:\Windows\System32`, // 重复
	}
	got := safePathList(entries, `C:\Java\bin`)
	if len(got) != 3 {
		t.Fatalf("应保留 2 系统项 + 1 Java 目录（去重），实际 %v", got)
	}
	if got[0] != `C:\Windows\System32` || got[2] != `C:\Java\bin` {
		t.Fatalf("顺序/内容不符: %v", got)
	}
}

func TestBuildSafeGamePATH(t *testing.T) {
	cur := `C:\Windows\System32;C:\Windows;C:\Users\joe\Downloads;C:\Temp;D:\Games\evil`
	safe, dropped, droppedList := buildSafeGamePATH(cur, `C:\Java\bin`)
	if !strings.HasPrefix(safe, `C:\Windows\System32;`) || !strings.Contains(safe, `C:\Java\bin`) {
		t.Fatalf("安全 PATH 不符: %q", safe)
	}
	if strings.Contains(safe, "Downloads") || strings.Contains(safe, `D:\Games`) {
		t.Fatalf("危险条目未被剔除: %q", safe)
	}
	if dropped != 3 {
		t.Fatalf("应剔除 3 条，实际 %d (%v)", dropped, droppedList)
	}
	// 空 PATH 输入。
	if safe2, d2, _ := buildSafeGamePATH("", `C:\Java`); safe2 != `C:\Java` || d2 != 0 {
		t.Fatalf("空 PATH 处理不符: %q d=%d", safe2, d2)
	}
}

func TestSanitizeGameEnv(t *testing.T) {
	env := []string{
		"JAVA_HOME=C:\\Java",
		"PATH=C:\\Windows\\System32;C:\\Users\\joe\\AppData\\Local\\Temp",
		"TEMP=C:\\Users\\joe\\AppData\\Local\\Temp",
	}
	out, dropped, droppedList := sanitizeGameEnv(env, `C:\Java\bin`)
	if dropped != 1 {
		t.Fatalf("应剔除 1 条: %d (%v)", dropped, droppedList)
	}
	var pathVal string
	for _, kv := range out {
		if strings.HasPrefix(kv, "PATH=") {
			pathVal = kv[len("PATH="):]
		}
	}
	if pathVal == "" || strings.Contains(pathVal, "Temp") {
		t.Fatalf("净化后 PATH 不符: %q", pathVal)
	}
	// 无 PATH 的环境：应追加一条。
	out2, _, _ := sanitizeGameEnv([]string{"JAVA_HOME=C:\\Java"}, `C:\Java\bin`)
	found := false
	for _, kv := range out2 {
		if strings.HasPrefix(kv, "PATH=") {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺少 PATH 时应追加: %v", out2)
	}
}
