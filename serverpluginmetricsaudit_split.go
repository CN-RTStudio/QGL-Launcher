package main

import "strings"

func spmCheckEndpoints(a *PluginMetricsAudit, cfg spxConfig) {
	for _, key := range spmEndpointKeys(cfg.Flat) {
		value := strings.TrimSpace(cfg.Flat[key])
		if value == "" {
			a.add(cfg.Rel, spmReasonBadValue, "遥测端点为空: "+key, false)
			continue
		}
		if strings.HasSuffix(key, "dsn") && strings.HasPrefix(strings.ToLower(value), "https://") {
			a.add(cfg.Rel, spmReasonDSN, "配置了外部错误上报 DSN: "+key, false)
			continue
		}
		kind, risky := spxURLRisk(value)
		switch kind {
		case "cleartext":
			a.add(cfg.Rel, spmReasonCleartext, "遥测端点使用明文 HTTP: "+key, true)
		case "credentials":
			a.add(cfg.Rel, spmReasonCreds, "遥测端点内嵌凭据: "+key, false)
		case "local-or-legacy":
			a.add(cfg.Rel, spmReasonCleartext, "遥测端点使用本地或旧式协议: "+key, true)
		case "path-shape":
			a.add(cfg.Rel, spmReasonCreds, "遥测端点包含路径穿越片段: "+key, true)
		case "https":
			if strings.Contains(strings.ToLower(value), "sentry") {
				a.add(cfg.Rel, spmReasonDSN, "配置了外部错误上报 DSN: "+key, false)
			}
		}

		if risky {
			continue
		}
	}
}
