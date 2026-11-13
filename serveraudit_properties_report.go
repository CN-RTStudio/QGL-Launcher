package main

import (
	"fmt"
)

func sprCheckWatchdog(a *PropertiesBudgetAudit, props sprProperties) {
	value, ok := props.Values["max-tick-time"]
	if !ok {
		return
	}
	n, valid := cfgParseInt(value)
	if !valid {
		a.add("server.properties", sprReasonBadValue, "max-tick-time 不是合法整数: "+value, false)
		return
	}
	if n < 0 {
		a.add("server.properties", sprReasonWatchdog, fmt.Sprintf("max-tick-time=%d 关闭了卡顿看门狗", n), true)
	} else if n == 0 {
		a.add("server.properties", sprReasonWatchdog, "max-tick-time=0 关闭了卡顿看门狗", true)
	} else if n < 30000 {
		a.add("server.properties", sprReasonBadValue, fmt.Sprintf("max-tick-time=%d 毫秒过于敏感", n), false)
	}
}

func sprCheckPorts(a *PropertiesBudgetAudit, props sprProperties) {
	ports := map[string]int{}
	for _, key := range []string{"server-port", "query.port", "rcon.port"} {
		n, ok := sprCheckInt(a, props, key)
		if !ok {
			continue
		}
		if n < 1 || n > 65535 {
			a.add("server.properties", sprReasonBadValue, fmt.Sprintf("%s=%d 超出端口范围", key, n), false)
			continue
		}
		ports[key] = n
	}
	if serverPort, ok := ports["server-port"]; ok {
		for _, key := range []string{"query.port", "rcon.port"} {
			if n, exists := ports[key]; exists && n == serverPort {
				a.add("server.properties", sprReasonPortClash, fmt.Sprintf("%s 与 server-port 同为 %d", key, n), false)
			}
		}
	}
}
