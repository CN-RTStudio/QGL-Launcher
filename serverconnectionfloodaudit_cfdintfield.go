package main

import (
	"fmt"
)

func cfdIntField(a *ConnectionFloodAudit, file, label, value string) (int, bool) {
	n, ok := cfgParseInt(value)
	if !ok {
		a.add(file, cfdReasonBadValue, label+" 不是合法整数: "+value, false)
		return 0, false
	}
	return n, true
}

func cfdCheckThrottle(a *ConnectionFloodAudit, file string, flat map[string]string) {
	value, ok := cfgLookup(flat, "settings.connection-throttle")
	if !ok {
		return
	}
	n, valid := cfdIntField(a, file, "connection-throttle", value)
	if !valid {
		return
	}
	if n < cfdThrottleMin {
		a.add(file, cfdThrottleOff, fmt.Sprintf("connection-throttle=%d 关闭了重连节流，可被快速重连放大", n), true)
		return
	}
	if n > cfdThrottleMax {
		a.add(file, cfdThrottleLoose, fmt.Sprintf("connection-throttle=%d 超过 %d 毫秒", n, cfdThrottleMax), false)
	}
}

func cfdCheckSpigot(a *ConnectionFloodAudit, flat map[string]string) {
	if value, ok := cfgLookup(flat, "settings.timeout-time"); ok {
		n, valid := cfdIntField(a, "spigot.yml", "settings.timeout-time", value)
		if valid {
			if n <= 0 {
				a.add("spigot.yml", cfdReasonBadValue, fmt.Sprintf("settings.timeout-time=%d 不是正数", n), false)
			} else if n > cfdTimeoutMax {
				a.add("spigot.yml", cfdTimeoutLoose, fmt.Sprintf("settings.timeout-time=%d 超过 %d 秒，慢连接占用时间过长", n, cfdTimeoutMax), false)
			}
		}
	}
	if value, ok := cfgLookup(flat, "settings.player-shuffle"); ok {
		n, valid := cfdIntField(a, "spigot.yml", "settings.player-shuffle", value)
		if valid && n < 0 {
			a.add("spigot.yml", cfdReasonBadValue, fmt.Sprintf("settings.player-shuffle=%d 为负数", n), false)
		}
	}
	if value, ok := cfgLookup(flat, "settings.connection-throttle"); ok {
		n, valid := cfdIntField(a, "spigot.yml", "settings.connection-throttle", value)
		if valid && n < cfdThrottleMin {
			a.add("spigot.yml", cfdThrottleOff, fmt.Sprintf("settings.connection-throttle=%d 关闭了重连节流", n), true)
		}
	}
}
