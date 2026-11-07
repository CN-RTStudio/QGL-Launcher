package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	sccMaxFindings     = 28
	sccMaxFile         = 512 * 1024
	sccReasonMiss      = "missing"
	sccReasonRead      = "unreadable"
	sccReasonOnline    = "online-mode-off"
	sccReasonWhitelist = "whitelist-off-with-permissive"
	sccReasonRconPass  = "rcon-password-weak"
	sccReasonRconOpen  = "rcon-exposed"
	sccReasonSecure    = "secure-profile-off"
	sccReasonSpawn     = "spawn-protection-off"
	sccReasonDistance  = "view-distance-mismatch"
	sccReasonPlayers   = "max-players-invalid"
	sccReasonOpsMany   = "too-many-operators"
	sccReasonQuery     = "query-enabled"
)

type ConsistencyFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type ConsistencyAudit struct {
	ServerDir string
	Findings  []ConsistencyFinding
}

func (a *ConsistencyAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= sccMaxFindings {
		return
	}
	a.Findings = append(a.Findings, ConsistencyFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *ConsistencyAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *ConsistencyAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *ConsistencyAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "服务端配置组合未发现风险"
	}
	sorted := make([]ConsistencyFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Detail < sorted[j].Detail
	})
	var b strings.Builder
	for i, f := range sorted {
		if i >= 12 {
			b.WriteString(fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		if i > 0 {
			b.WriteString("；")
		}
		b.WriteString(f.Reason)
		if f.Detail != "" {
			b.WriteString("(")
			b.WriteString(f.Detail)
			b.WriteString(")")
		}
	}
	return b.String()
}

func sccBool(props map[string]string, key string) (bool, bool) {
	raw, ok := props[key]
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "on", "yes":
		return true, true
	case "false", "off", "no":
		return false, true
	}
	return false, false
}

func sccCountOps(serverDir string) int {
	path := filepath.Join(serverDir, "ops.json")
	data, err := readBoundedFile(path, sccMaxFile)
	if err != nil {
		return -1
	}
	return strings.Count(string(data), "\"uuid\"")
}

func AuditServerConfigConsistency(serverDir string) *ConsistencyAudit {
	a := &ConsistencyAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("server.properties", sccReasonMiss, "未配置服务器目录", false)
		return a
	}
	const propsRel = "server.properties"
	path := filepath.Join(serverDir, propsRel)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(propsRel, sccReasonMiss, "未找到 server.properties", false)
		return a
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(propsRel, sccReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(propsRel, sccReasonRead, "属性文件是符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, sccMaxFile)
	if err != nil {
		a.add(propsRel, sccReasonRead, err.Error(), true)
		return a
	}
	props := pxParseProperties(string(data))
	if len(props) == 0 {
		a.add(propsRel, sccReasonMiss, "属性文件为空", false)
		return a
	}

	if online, ok := sccBool(props, "online-mode"); ok && !online {
		a.add(propsRel, sccReasonOnline, "离线模式允许伪造身份", true)
	}
	if secure, ok := sccBool(props, "enforce-secure-profile"); ok && !secure {
		a.add(propsRel, sccReasonSecure, "关闭安全签名校验", false)
	}
	if white, ok := sccBool(props, "white-list"); ok && !white {
		if level, ok2 := sccBool(props, "enforce-whitelist"); ok2 && level {
			a.add(propsRel, sccReasonWhitelist, "强制白名单但白名单未启用", true)
		}
	}
	if rcon, ok := sccBool(props, "enable-rcon"); ok && rcon {
		pass := strings.TrimSpace(props["rcon.password"])
		if pass == "" || cfgIsPlaceholder(pass) || len(pass) < 8 {
			a.add(propsRel, sccReasonRconPass, "RCON 密码为空、过短或占位", true)
		}
		port := strings.TrimSpace(props["rcon.port"])
		if port == "" || port == "25575" {
			a.add(propsRel, sccReasonRconOpen, "RCON 使用默认端口", false)
		}
	}
	if protect, ok := sccBool(props, "spawn-protection"); ok && protect {
		if radius, ok2 := cfgParseInt(props["spawn-protection"]); ok2 {
			if radius <= 0 {
				a.add(propsRel, sccReasonSpawn, "出生点保护半径为 0", false)
			}
		}
	}
	view, okView := cfgParseInt(props["view-distance"])
	sim, okSim := cfgParseInt(props["simulation-distance"])
	if okView && okSim && sim > view {
		a.add(propsRel, sccReasonDistance, fmt.Sprintf("simulation=%d > view=%d", sim, view), false)
	}
	if max, ok := cfgParseInt(props["max-players"]); ok && (max <= 0 || max > 200) {
		a.add(propsRel, sccReasonPlayers, "max-players="+strconv.Itoa(max), false)
	}
	if query, ok := sccBool(props, "enable-query"); ok && query {
		a.add(propsRel, sccReasonQuery, "查询端口对外暴露服务器信息", false)
	}
	if count := sccCountOps(serverDir); count > 8 {
		a.add("ops.json", sccReasonOpsMany, fmt.Sprintf("%d 名管理员", count), false)
	}
	return a
}
