package main

import (
	"path/filepath"
	"strconv"
)

func AuditServerMaxPlayers(serverDir string) *MaxPlayersAudit {
	a := &MaxPlayersAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(smpReasonCount, "未配置服务器目录", false)
		return a
	}
	data, err := readBoundedFile(filepath.Join(serverDir, "server.properties"), 256*1024)
	if err != nil {
		a.add(smpReasonCount, "无法读取 server.properties", false)
		return a
	}
	props := pxParseProperties(string(data))
	if len(props) == 0 {
		a.add(smpReasonCount, "属性文件为空", false)
		return a
	}
	if raw, ok := props["max-players"]; ok {
		value, parsed := cfgParseInt(raw)
		switch {
		case !parsed || value <= 0:
			a.add(smpReasonCount, "max-players 非法: "+cfgStripQuotes(raw), true)
		case value > 200:
			a.add(smpReasonMany, "max-players="+strconv.Itoa(value)+" 超出单机承载", false)
		}
	}
	if raw, ok := props["player-idle-timeout"]; ok {
		value, parsed := cfgParseInt(raw)
		if !parsed || value <= 0 {
			a.add(smpReasonIdle, "空闲踢出已关闭，连接可长期挂起", false)
		}
	}
	if raw, ok := props["rate-limit"]; ok {
		value, parsed := cfgParseInt(raw)
		if !parsed || value <= 0 {
			a.add(smpReasonRate, "报文限流为 0，洪水攻击无制动", false)
		}
	}
	if raw, ok := props["view-distance"]; ok {
		value, parsed := cfgParseInt(raw)
		if !parsed || value < 3 || value > 32 {
			a.add(smpReasonView, "view-distance="+cfgStripQuotes(raw), false)
		}
	}
	if raw, ok := props["simulation-distance"]; ok {
		value, parsed := cfgParseInt(raw)
		if !parsed || value < 3 || value > 32 {
			a.add(smpReasonSim, "simulation-distance="+cfgStripQuotes(raw), false)
		}
	}
	if raw, ok := props["max-world-size"]; ok {
		if value, parsed := cfgParseInt(raw); !parsed || value <= 0 {
			a.add(smpReasonView, "世界尺寸上限非法: "+cfgStripQuotes(raw), false)
		}
	}
	return a
}
