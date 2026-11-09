package main

import (
	"fmt"
	"os"
	"strings"
)

func AuditServerWatchdog(serverDir string) *WatchdogAudit {
	a := &WatchdogAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", spwReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", spwReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", spwReasonMissing, "服务器目录不存在", false)
		return a
	}

	if text, ok := spwLoadText(a, serverDir, "server.properties", spwMaxProps); ok {
		props := pxParseProperties(text)
		if raw, found := props["max-tick-time"]; found {
			if value, parsed := cfgParseInt(strings.TrimSpace(raw)); parsed {
				if value < 0 {
					a.add("server.properties", spwReasonDisabled, "max-tick-time<0 关闭看门狗", false)
				} else if value == 0 {
					a.add("server.properties", spwReasonBadValue, "max-tick-time=0", true)
				} else if value > spwMaxTimeout*1000 {
					a.add("server.properties", spwReasonHigh, "max-tick-time 过大", false)
				}
			} else {
				a.add("server.properties", spwReasonBadValue, "max-tick-time 非整数", true)
			}
		}
	}

	restartOnCrash := false
	restartScript := ""
	if text, ok := spwLoadText(a, serverDir, "spigot.yml", spwMaxYAML); ok {
		flat := cfgFlattenYAML(text)
		if value, found := spwBool(flat, "settings.restart-on-crash"); found {
			restartOnCrash = value
			if !value {
				a.add("spigot.yml", spwReasonRestartOff, "restart-on-crash 已关闭", false)
			}
		}
		if timeoutText, found := spwText(flat, "settings.timeout-time"); found {
			if timeout, parsed := cfgParseInt(timeoutText); !parsed {
				a.add("spigot.yml", spwReasonBadValue, "timeout-time 非整数", true)
			} else if timeout < spwMinTimeout {
				a.add("spigot.yml", spwReasonLow, fmt.Sprintf("timeout-time=%d 过低", timeout), false)
			} else if timeout > spwMaxTimeout {
				a.add("spigot.yml", spwReasonHigh, fmt.Sprintf("timeout-time=%d 过高", timeout), false)
			}
		}
		if script, found := spwText(flat, "settings.restart-script"); found {
			restartScript = script
		}
	}

	if restartOnCrash {
		if reason, detail := spwScriptProblem(restartScript); reason != "" {
			blocking := reason != spwReasonRestartOff
			a.add("spigot.yml", reason, detail, blocking)
		}
	}

	if text, ok := spwLoadText(a, serverDir, "config/paper-global.yml", spwMaxYAML); ok {
		flat := cfgFlattenYAML(text)
		if everyText, found := spwText(flat, "watchdog.early-warning-every"); found {
			if every, parsed := cfgParseInt(everyText); !parsed {
				a.add("config/paper-global.yml", spwReasonEarlyBad, "early-warning-every 非整数", true)
			} else if every < 0 {
				a.add("config/paper-global.yml", spwReasonEarlyBad, "early-warning-every 为负值", true)
			} else if every == 0 {
				a.add("config/paper-global.yml", spwReasonEarlyOff, "early-warning-every 已关闭", false)
			}
		}
		if delayText, found := spwText(flat, "watchdog.early-warning-delay"); found {
			if delay, parsed := cfgParseInt(delayText); !parsed || delay < 0 {
				a.add("config/paper-global.yml", spwReasonEarlyBad, "early-warning-delay 非法", true)
			}
		}
	}
	return a
}
