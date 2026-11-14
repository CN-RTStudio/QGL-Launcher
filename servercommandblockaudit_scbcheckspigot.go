package main

import (
	"fmt"
	"strings"
)

func scbCheckSpigot(a *CommandBlockAudit, flat map[string]string, text string) {
	silent, ok := cfgLookup(flat, "commands.silent-commandblock-console")
	if ok && strings.EqualFold(strings.TrimSpace(silent), "true") {
		a.add("spigot.yml", scbReasonSilent, "commands.silent-commandblock-console=true，命令方块输出不再进入控制台", false)
	}

	items := scbScanSpamExclusions(text)
	if len(items) > 0 {
		if len(items) > 8 {
			a.add("spigot.yml", scbReasonSpamList, fmt.Sprintf("commands.spam-exclusions 条目 %d 个，命令刷屏限制被大幅放宽", len(items)), false)
		}
		for _, item := range items {
			lower := strings.ToLower(item)
			if strings.Contains(lower, "/*") || strings.HasPrefix(lower, "/") {
				a.add("spigot.yml", scbReasonSpamList, "commands.spam-exclusions 放宽到整类命令: "+item, false)
			}
		}
	}

	tabComplete, ok := cfgLookup(flat, "commands.tab-complete")
	if ok {
		lower := strings.ToLower(strings.TrimSpace(tabComplete))
		if lower != "0" && lower != "-1" && lower != "1" {
			if _, perr := cfgParseInt(tabComplete); !perr {
				a.add("spigot.yml", scbReasonBadValue, "commands.tab-complete 取值非法: "+tabComplete, false)
			}
		}
	}
}
