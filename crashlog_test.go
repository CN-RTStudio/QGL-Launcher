package main

import (
	"strings"
	"testing"
)

func TestRedactCrashTextUserDir(t *testing.T) {
	in := `启动目录 C:\Users\joe\AppData\Roaming\QGL
JVM 参数 -Duser.home=C:/Users/joe
hs_err 位于 C:\Users\joe\AppData\Local\Temp\hs_err_pid1.log`
	got := redactCrashText(in, "", "", "joe")
	if strings.Contains(got, `joe`) {
		t.Fatalf("用户目录未被脱敏: %s", got)
	}
	if !strings.Contains(got, redactedUser) {
		t.Fatalf("缺少占位符: %s", got)
	}
}

func TestRedactCrashTextDirs(t *testing.T) {
	qgl := `C:\Program Files\QGL`
	mc := `D:\Minecraft\.minecraft`
	in := `QGL 根: C:\Program Files\QGL\config.json
游戏: D:\Minecraft\.minecraft\versions\1.20.4\1.20.4.json
正斜杠: C:/Program Files/QGL/data`
	got := redactCrashText(in, qgl, mc, "")
	if strings.Contains(got, `Program Files`) || strings.Contains(got, `Minecraft`) {
		t.Fatalf("目录未脱敏: %s", got)
	}
	if !strings.Contains(got, redactedHome) {
		t.Fatalf("缺少目录占位符: %s", got)
	}
}

func TestRedactCrashTextTokens(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	hex := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	in := "token=" + jwt + " sha=" + hex
	got := redactCrashText(in, "", "", "")
	if strings.Contains(got, jwt) {
		t.Fatalf("JWT 未脱敏: %s", got)
	}
	if strings.Contains(got, "deadbeef") {
		t.Fatalf("长十六进制未脱敏: %s", got)
	}
	if !strings.Contains(got, redactedToken) || !strings.Contains(got, redactedHex) {
		t.Fatalf("缺少令牌占位符: %s", got)
	}
}

func TestRedactCrashTextEmptyAndPreview(t *testing.T) {
	if got := redactCrashText("", `C:\QGL`, `D:\mc`, "u"); got != "" {
		t.Fatalf("空文本应原样返回: %q", got)
	}
	preview := crashTextPreview("  abcdefgh  ", 4)
	if preview != "abcd..." {
		t.Fatalf("预览截断不符: %q", preview)
	}
	if crashTextPreview("abc", 10) != "abc" {
		t.Fatal("短文本不应截断")
	}
}

func TestReplaceDirCI(t *testing.T) {
	in := `C:\Minecraft\Data C:/Minecraft/data c:\minecraft\DATA`
	got := replaceDirCI(in, `C:\Minecraft`, redactedHome)
	if strings.Contains(got, "minecraft") && strings.Contains(got, "Minecraft") {
		t.Fatalf("大小写变体未全覆盖: %s", got)
	}
	if strings.Count(got, redactedHome) < 3 {
		t.Fatalf("替换次数不足: %s", got)
	}
}
