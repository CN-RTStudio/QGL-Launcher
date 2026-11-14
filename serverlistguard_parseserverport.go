package main

import (
	"strconv"
)

func parseServerPort(raw string, max int) (int, bool) {
	if raw == "" {
		return 0, false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 || v > max {
		return 0, false
	}
	return v, true
}

type ServerEntry struct {
	Host   string
	Port   int
	Name   string
	Kind   ServerKind
	Source string // 原始行（净化后），供审计
}

// ParseServerAddress 解析 "host[:port]"；port 缺省为 25565。
// 拒绝：空 host、控制字符、空格、引号、分号、逗号、路径分隔、URL 方案前缀、
// 端口越界或非数字。
