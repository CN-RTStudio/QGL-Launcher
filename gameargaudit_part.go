package main

import "strings"

func (g *GameArgAudit) HasCritical() bool { return g.Critical > 0 }

// FirstCriticalCode 返回首个 critical 代码。
func (g *GameArgAudit) FirstCriticalCode() string {
	for _, f := range g.Findings {
		if f.Severity == launchSeverityCritical {
			return f.Code
		}
	}
	return ""
}

// normalizeGameFlag 把一个 token 规整成“不带前导连字符的小写 flag 名”。
// "--server" / "-server" / "--server=..." -> "server"；不是 flag（不以 - 开头，或
// 单纯 "-"）返回 ok=false。operandSeparated=true 表示形如 "--server value"（下一条是
// 值）；等于 false 表示自携带值 "--server=x" 或裸 flag。
func normalizeGameFlag(token string) (name string, separated bool, ok bool) {
	t := token
	if len(t) < 2 || t[0] != '-' {
		return "", false, false
	}
	t = strings.TrimLeft(t, "-")
	if t == "" {
		return "", false, false
	}
	// 形如 -Dxxx / -X 这类 JVM 形态不应出现在游戏段，交给调用方按值记录；这里只识别
	// 标准的 --flag / --flag=value。
	if idx := strings.IndexByte(t, '='); idx >= 0 {
		return strings.ToLower(t[:idx]), false, true
	}
	return strings.ToLower(t), true, true
}

// gameFindingsContainCode 报告一组 finding 中是否含指定 code（生产代码可用）。
func gameFindingsContainCode(fs []LaunchFinding, code string) bool {
	for _, f := range fs {
		if f.Code == code {
			return true
		}
	}
	return false
}
