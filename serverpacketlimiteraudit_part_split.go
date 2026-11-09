package main

import (
	"fmt"
	"os"
	"strings"
)

func pklValidBlockName(name string) bool {
	if name == "" || len(name) > 96 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == ':' || c == '.' || c == '-' || c == '#'
		if !ok {
			return false
		}
	}
	return true
}

func pklCheckChunkLoading(a *PacketLimiterAudit, flat map[string]string) {
	file := "config/paper-global.yml"
	if value, ok := cfgLookup(flat, "chunk-loading.max-auto-save-chunks-per-tick"); ok {
		n, valid := cfgParseInt(value)
		if !valid || n <= 0 {
			a.add(file, pklReasonBadValue, "max-auto-save-chunks-per-tick 非法: "+value, false)
			return
		}
		if n > pklMaxAutoSave {
			a.add(file, pklReasonAutoSave, fmt.Sprintf("max-auto-save-chunks-per-tick=%d 超过 %d", n, pklMaxAutoSave), false)
		}
	}
	if value, ok := cfgLookup(flat, "chunk-loading.prevent-moving-into-unloaded-chunks"); ok {
		prevent, valid := pklBool(a, file, "prevent-moving-into-unloaded-chunks", value)
		if valid && !prevent {
			a.add(file, pklReasonAutoSave, "允许玩家进入未加载区块，可被用于拉爆区块加载", false)
		}
	}
}

func pklCheckOverrides(a *PacketLimiterAudit, flat map[string]string) {
	file := "config/paper-global.yml"
	count := 0
	for key, value := range flat {
		if !strings.HasPrefix(key, "packet-limiter.overrides.") {
			continue
		}
		if !strings.HasSuffix(key, ".max-packet-rate") {
			continue
		}
		count++
		n, valid := cfgParseInt(value)
		if !valid || n <= 0 {
			a.add(file, pklReasonBadValue, key+" 非法: "+value, false)
			continue
		}
		if n > pklMaxRate {
			a.add(file, pklReasonLimiterLoose, fmt.Sprintf("%s=%d 超过 %d", key, n, pklMaxRate), false)
		}
	}
	if count > 64 {
		a.add(file, pklReasonLimiterLoose, fmt.Sprintf("overrides 条目 %d 过多", count), false)
	}
}

func AuditServerPacketLimiter(serverDir string) *PacketLimiterAudit {
	a := &PacketLimiterAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", pklReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", pklReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", pklReasonMissing, "服务器目录不存在", false)
		return a
	}
	flat := pklLoadFlat(a, serverDir, "config/paper-global.yml")
	if flat == nil {
		a.add(".", pklReasonMissing, "未发现 paper-global.yml", false)
		return a
	}
	pklCheckLimiter(a, flat)
	pklCheckAntiXray(a, flat)
	pklCheckChunkLoading(a, flat)
	pklCheckOverrides(a, flat)
	return a
}
