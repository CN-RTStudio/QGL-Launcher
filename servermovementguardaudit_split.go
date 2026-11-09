package main

import (
	"fmt"
)

func smaCheckProperties(a *MovementGuardAudit, props map[string]string) {
	flight, flightKnown := smaBool(props, "allow-flight")
	if flightKnown && flight {
		a.add("server.properties", smaReasonFlight, "allow-flight=true，客户端可绕过移动校验飞行", false)
	}

	idle, idleKnown, idleValid := smaInt(props, "player-idle-timeout")
	if idleKnown {
		switch {
		case !idleValid:
			a.add("server.properties", smaReasonBadValue, "player-idle-timeout 不是合法整数", false)
		case idle == 0:
			a.add("server.properties", smaReasonIdle, "player-idle-timeout=0，挂机玩家永不被踢出", false)
		case idle < smaMinIdleMinutes:
			a.add("server.properties", smaReasonIdle, fmt.Sprintf("player-idle-timeout=%d 低于 %d 分钟", idle, smaMinIdleMinutes), false)
		}
	}

	spawn, spawnKnown, spawnValid := smaInt(props, "spawn-protection")
	if spawnKnown {
		switch {
		case !spawnValid:
			a.add("server.properties", smaReasonBadValue, "spawn-protection 不是合法整数", false)
		case spawn == 0:
			a.add("server.properties", smaReasonSpawnProt, "spawn-protection=0，出生点保护关闭", false)
		case spawn < 0:
			a.add("server.properties", smaReasonBadValue, fmt.Sprintf("spawn-protection=%d 为负值", spawn), false)
		}
	}

	size, sizeKnown, sizeValid := smaInt(props, "max-world-size")
	if sizeKnown {
		switch {
		case !sizeValid:
			a.add("server.properties", smaReasonWorldSize, "max-world-size 不是合法整数", true)
		case size < 1 || size > smaMaxWorldSize:
			a.add("server.properties", smaReasonWorldSize, fmt.Sprintf("max-world-size=%d 超出 1..%d", size, smaMaxWorldSize), true)
		}
	}

	players, playersKnown, playersValid := smaInt(props, "max-players")
	if playersKnown {
		switch {
		case !playersValid:
			a.add("server.properties", smaReasonBadValue, "max-players 不是合法整数", false)
		case players < 1:
			a.add("server.properties", smaReasonBadValue, fmt.Sprintf("max-players=%d 小于 1", players), false)
		case players > smaMaxPlayersSoft:
			a.add("server.properties", smaReasonPlayerCap, fmt.Sprintf("max-players=%d 高于 %d", players, smaMaxPlayersSoft), false)
		}
	}

	debugOn, debugKnown := smaBool(props, "debug")
	if debugKnown && debugOn {
		a.add("server.properties", smaReasonDebug, "debug=true，输出包含内部路径与堆栈的调试信息", false)
	}
}
