package main

import (
	"strings"
)

func skScanText(a *StartupSecretAudit, rel, text string) bool {
	plain := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "rem ") {
			continue
		}
		lower := strings.ToLower(line)
		if skLineHasSecret(lower) {
			a.add(rel, skReasonPlainSecret, "启动脚本包含明文口令赋值", true)
			plain = true
		}
		if skLineHasPropSecret(lower) {
			a.add(rel, skReasonPropSecret, "JVM 系统属性携带明文口令", true)
			plain = true
		}
		if skLineHasURLCreds(line) {
			a.add(rel, skReasonURLCreds, "启动脚本 URL 内嵌账号口令", true)
			plain = true
		}
		if strings.Contains(lower, "--accesstoken") || strings.Contains(lower, "-accesstoken") {
			a.add(rel, skReasonTokenArg, "命令行参数直接传递访问令牌", true)
			plain = true
		}
		if strings.Contains(lower, "rcon-cli") && (strings.Contains(lower, " -p ") || strings.Contains(lower, "--password")) {
			a.add(rel, skReasonRCONArg, "RCON 客户端参数携带明文口令", true)
			plain = true
		}
		if strings.HasPrefix(lower, "export ") || strings.HasPrefix(lower, "set ") || strings.HasPrefix(lower, "setx ") {
			if skLineHasSecret(lower) {
				a.add(rel, skReasonEnvSecret, "环境变量写入明文口令", true)
				plain = true
			}
		}
	}
	return plain
}
