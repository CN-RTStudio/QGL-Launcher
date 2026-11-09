package main

import (
	"fmt"
)

func sprCheckInt(a *PropertiesBudgetAudit, props sprProperties, key string) (int, bool) {
	value, ok := props.Values[key]
	if !ok {
		return 0, false
	}
	n, valid := cfgParseInt(value)
	if !valid {
		a.add("server.properties", sprReasonBadValue, key+" 不是合法整数: "+value, false)
		return 0, false
	}
	return n, true
}

func sprCheckViewDistance(a *PropertiesBudgetAudit, props sprProperties) {
	view, hasView := sprCheckInt(a, props, "view-distance")
	simulation, hasSimulation := sprCheckInt(a, props, "simulation-distance")
	if hasView {
		if view > sprMaxViewDistance {
			a.add("server.properties", sprReasonViewLarge, fmt.Sprintf("view-distance=%d 超过 %d，区块与实体负载放大", view, sprMaxViewDistance), false)
		}
		if view < sprMinViewDistance {
			a.add("server.properties", sprReasonViewSmall, fmt.Sprintf("view-distance=%d 低于 %d", view, sprMinViewDistance), false)
		}
	}
	if hasSimulation && hasView && simulation > view {
		a.add("server.properties", sprReasonSimDistance, fmt.Sprintf("simulation-distance=%d 大于 view-distance=%d", simulation, view), false)
	}
}
