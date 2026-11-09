package main

import (
	"fmt"
)

func snmBool(props map[string]string, key string) (bool, bool) {
	return propsBoolValue(props, key)
}

func AuditServerOnlineMode(serverDir string) *OnlineModeAudit {
	a := &OnlineModeAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(snmMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := snmReadProps(serverDir, a)
	if !ok {
		return a
	}
	if online, has := snmBool(props, "online-mode"); has && !online {
		a.add(snmOffline, "离线模式允许任意伪造用户名与 UUID", true)
	}
	if secure, has := snmBool(props, "enforce-secure-profile"); has && !secure {
		a.add(snmSecureOff, "关闭聊天签名校验，可被重放冒充", false)
	}
	if proxy, has := snmBool(props, "prevent-proxy-connections"); has && !proxy {
		if online, has2 := snmBool(props, "online-mode"); has2 && online {
			a.add(snmProxyOpen, "在线模式却允许代理转发连接", false)
		}
	}
	raw, has := props["network-compression-threshold"]
	if has {
		value, parsed := cfgParseInt(raw)
		if parsed {
			if value < 0 {
				a.add(snmCompressOff, "关闭网络压缩，放大带宽消耗", false)
			} else if value >= 0 && value < 64 {
				a.add(snmCompressLow, fmt.Sprintf("压缩阈值 %d 过低，易被压缩炸弹拖垮", value), false)
			}
		} else {
			a.add(snmCompressLow, "压缩阈值不是整数: "+cfgStripQuotes(raw), false)
		}
	}
	return a
}
