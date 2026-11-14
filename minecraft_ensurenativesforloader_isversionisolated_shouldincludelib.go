package main

import (

)

func (a *App) shouldIncludeLib(lib Library) bool {
	if len(lib.Rules) == 0 {
		return true // 没有 rules，默认包含
	}

	allow := false
	for _, rule := range lib.Rules {
		osMatch := true
		if rule.OS != nil {
			osMatch = rule.OS.Name == "windows"
		}

		if rule.Action == "allow" {
			if osMatch {
				allow = true
			}
		} else if rule.Action == "disallow" {
			if osMatch {
				allow = false
			}
		}
	}

	return allow
}

// libGroupArtifact 从 Maven 坐标中提取 group:artifact（不含版本号）
// 例如 "org.apache.logging.log4j:log4j-core:2.17.1" -> "org.apache.logging.log4j:log4j-core"
