package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func smaCheckPaper(a *MovementGuardAudit, flat map[string]string) {
	if value, ok := cfgLookup(flat, "misc.max-joins-per-tick"); ok {
		n, valid := cfgParseInt(value)
		if !valid {
			a.add("config/paper-global.yml", smaReasonBadValue, "misc.max-joins-per-tick 不是合法整数", false)
			return
		}
		if n < 1 {
			a.add("config/paper-global.yml", smaReasonBadValue, fmt.Sprintf("misc.max-joins-per-tick=%d 小于 1", n), false)
		}
	}
	if value, ok := cfgLookup(flat, "collisions.enable-player-collisions"); ok {
		on, known := spxBool(value)
		if !known {
			a.add("config/paper-global.yml", smaReasonBadValue, "collisions.enable-player-collisions 取值非法: "+value, false)
			return
		}
		if on {
			a.add("config/paper-global.yml", smaReasonFlight, "collisions.enable-player-collisions=true，玩家推挤可绕过移动校验", false)
		}
	}
}

func AuditServerMovementGuards(serverDir string) *MovementGuardAudit {
	a := &MovementGuardAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", smaReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", smaReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", smaReasonMissing, "服务器目录不存在", false)
		return a
	}

	if text, ok := smaLoadText(a, serverDir, "server.properties", smaMaxProps); ok {
		props := pxParseProperties(text)
		if len(props) == 0 && strings.TrimSpace(text) != "" {
			a.add("server.properties", smaReasonBadValue, "server.properties 未解析出任何键值", false)
		}
		smaCheckProperties(a, props)
	}

	if text, ok := smaLoadText(a, serverDir, filepath.Join("config", "paper-global.yml"), smaMaxProps); ok {
		smaCheckPaper(a, cfgFlattenYAML(text))
	}

	if len(a.Findings) == 0 {
		a.add("server.properties", smaReasonOK, "未发现移动与容量相关配置", false)
	}
	return a
}
