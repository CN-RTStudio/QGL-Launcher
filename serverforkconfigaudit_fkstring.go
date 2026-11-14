package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func fkString(props map[string]string, key string) (string, bool) {
	for _, candidate := range fkKeyVariants(key) {
		raw, ok := props[candidate]
		if !ok {
			continue
		}
		return strings.Trim(strings.TrimSpace(raw), `"'`), true
	}
	return "", false
}

func fkKeyVariants(key string) []string {
	normalized := strings.ToLower(key)
	return []string{
		normalized,
		"settings." + normalized,
		"world-settings.default." + normalized,
		"world-settings.default." + normalized,
	}
}

func fkInspectFile(a *ForkConfigAudit, dir, name string) bool {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	a.Files = append(a.Files, name)
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(name, fkReasonSymlink, "分支配置文件是符号链接", true)
		return true
	}
	if info.Size() > fkMaxConfigBytes {
		a.add(name, fkReasonTooLarge, "分支配置文件超过体积预算", true)
		return true
	}
	if info.Mode().Perm()&0o022 != 0 {
		a.add(name, fkReasonWorldWritable, "分支配置文件可被其他用户改写", true)
	}
	data, readErr := readBoundedFile(path, fkMaxConfigBytes)
	if readErr != nil {
		a.add(name, fkReasonUnreadable, "分支配置文件不可读", true)
		return true
	}
	fkScanText(a, name, string(data))
	return true
}

func fkScanText(a *ForkConfigAudit, name, text string) {
	props := fkFlattenConfig(text)
	if len(props) == 0 {
		return
	}
	if value, ok := fkNumber(props, "connection-throttle"); ok && value < 0 {
		a.add(name, fkReasonThrottleOff, "连接节流被关闭，登录洪水不限速", false)
	}
	if enabled, ok := fkBool(props, "settings.bungeecord"); ok && enabled {
		a.add(name, fkReasonLegacyProxy, "启用旧版 BungeeCord 代理转发", false)
	}
	if enabled, ok := fkBool(props, "bungeecord"); ok && enabled {
		a.add(name, fkReasonLegacyProxy, "启用旧版 BungeeCord 代理转发", false)
	}
	if value, ok := fkString(props, "settings.velocity-support.secret"); ok && value == "" {
		a.add(name, fkReasonProxySecret, "Velocity 转发密钥为空", true)
	}
	if forwarding, ok := fkBool(props, "settings.velocity-support.enabled"); ok && forwarding {
		if value, has := fkString(props, "settings.velocity-support.secret"); !has || len(value) < 16 {
			a.add(name, fkReasonProxySecret, "Velocity 转发密钥缺失或过短", true)
		}
	}
	if enabled, ok := fkBool(props, "anti-xray.enabled"); ok && !enabled {
		a.add(name, fkReasonXrayOff, "反矿透被关闭", false)
	}
	if enabled, ok := fkBool(props, "packet-limiter.enabled"); ok && !enabled {
		a.add(name, fkReasonPacketLimiter, "数据包限流被关闭", false)
	}
	if value, ok := fkNumber(props, "packet-limiter.max-packet-rate"); ok && value > 500 {
		a.add(name, fkReasonPacketRate, fmt.Sprintf("数据包速率上限 %d 过高", value), false)
	}
	if value, ok := fkNumber(props, "max-entity-collisions"); ok && value > 8 {
		a.add(name, fkReasonCollisions, fmt.Sprintf("实体碰撞上限 %d 过高", value), false)
	}
	if value, ok := fkNumber(props, "entity-activation-range.animals"); ok && value > 32 {
		a.add(name, fkReasonActivationRange, fmt.Sprintf("动物激活范围 %d 过大", value), false)
	}
	if value, ok := fkNumber(props, "view-distance"); ok && value > 12 {
		a.add(name, fkReasonViewDistance, fmt.Sprintf("视野距离 %d 超过推荐上限", value), false)
	}
	if value, ok := fkNumber(props, "ticks-per.autosave"); ok && value > 6000 {
		a.add(name, fkReasonSaveInterval, fmt.Sprintf("自动保存间隔 %d tick 过长", value), false)
	}
	if value, ok := fkNumber(props, "timeout-time"); ok && value <= 0 {
		a.add(name, fkReasonIdleTimeout, "空闲超时被关闭", false)
	}
	for key, raw := range props {
		lower := strings.ToLower(raw)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "http:") {
			a.add(name, fkReasonUnknownValue, fmt.Sprintf("配置项 %s 使用明文 http 地址", key), false)
		}
	}
}
