package main

import (
	"fmt"
	"strings"
)

func pxCheckPort(a *ServerPortAudit, props map[string]string, key string) int {
	raw := props[key]
	if strings.TrimSpace(raw) == "" {
		a.Ports[key] = 0
		return 0
	}
	port, ok := pxParsePort(raw)
	a.Ports[key] = port
	if !ok {
		a.add(pxReasonBadPort, fmt.Sprintf("%s=%q 不是合法端口", key, raw), true)
		return 0
	}
	if port < 1024 {
		a.add(pxReasonLowPort, fmt.Sprintf("%s=%d 落在特权端口区间", key, port), false)
	}
	if label, bad := pxForbiddenPorts[port]; bad {
		a.add(pxReasonPortConflict, fmt.Sprintf("%s=%d 与常见服务端口冲突: %s", key, port, label), false)
	}
	return port
}
