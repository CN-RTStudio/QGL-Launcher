package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	motMaxFindings = 16
	motMaxFile     = 256 * 1024
	motMaxMOTD     = 512
	motMiss        = "properties-missing"
	motRead        = "properties-unreadable"
	motLink        = "properties-symlink"
	motEmpty       = "properties-empty"
	motMOTDEmpty   = "motd-empty"
	motMOTDLong    = "motd-too-long"
	motMOTDControl = "motd-control-characters"
	motMOTDColor   = "motd-formatting-codes"
	motMOTDHost    = "motd-address-leak"
	motSecureChat  = "secure-profile-disabled"
	motHidePlayers = "online-players-exposed"
	motVersionLeak = "version-exposed"
)

var motAddressPattern = regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}|([a-z0-9-]+\.)+(com|net|org|io|cn|top|xyz)`)

type MotdConfigFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type MotdConfigAudit struct {
	ServerDir string
	Findings  []MotdConfigFinding
}

func (a *MotdConfigAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= motMaxFindings {
		return
	}
	a.Findings = append(a.Findings, MotdConfigFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *MotdConfigAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *MotdConfigAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *MotdConfigAudit) Describe() string {
	return describeAuditFindings("MOTD 与状态响应未泄露敏感信息", a.Findings, 10,
		func(f MotdConfigFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f MotdConfigFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func motReadProps(serverDir string, a *MotdConfigAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(motMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(motRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(motLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, motMaxFile)
	if err != nil {
		a.add(motRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(motEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}

func motBool(props map[string]string, key string) (bool, bool) {
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

func motAuditMOTD(props map[string]string, a *MotdConfigAudit) {
	raw, ok := props["motd"]
	if !ok {
		a.add(motMOTDEmpty, "未配置 motd", false)
		return
	}
	text := cfgStripQuotes(strings.TrimSpace(raw))
	if text == "" {
		a.add(motMOTDEmpty, "motd 为空", false)
		return
	}
	if len(text) > motMaxMOTD {
		a.add(motMOTDLong, fmt.Sprintf("motd 长度 %d 超过 %d", len(text), motMaxMOTD), true)
	}
	if strings.ContainsAny(text, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f") {
		a.add(motMOTDControl, "motd 含控制字符", false)
	}
	if strings.Contains(text, "\u00a7") {
		a.add(motMOTDColor, "motd 含 § 格式化代码", false)
	}
	if motAddressPattern.MatchString(strings.ToLower(text)) {
		a.add(motMOTDHost, "motd 暴露域名或 IP", true)
	}
}

func AuditServerMotdConfig(serverDir string) *MotdConfigAudit {
	a := &MotdConfigAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(motMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := motReadProps(serverDir, a)
	if !ok {
		return a
	}
	motAuditMOTD(props, a)
	if value, has := motBool(props, "enforce-secure-profile"); has && !value {
		a.add(motSecureChat, "enforce-secure-profile=false 允许未签名聊天", false)
	}
	if value, has := motBool(props, "hide-online-players"); has && !value {
		a.add(motHidePlayers, "在线玩家名单对外可见", false)
	}
	if value, has := motBool(props, "hide-version"); has && !value {
		a.add(motVersionLeak, "状态响应暴露服务器版本", false)
	}
	return a
}
