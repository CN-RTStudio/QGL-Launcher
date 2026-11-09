package main

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	snmMaxFindings = 18
	snmMaxFile     = 256 * 1024
	snmMiss        = "properties-missing"
	snmRead        = "properties-unreadable"
	snmOffline     = "online-mode-off"
	snmSecureOff   = "secure-profile-off"
	snmProxyOpen   = "proxy-connections-allowed"
	snmCompressOff = "compression-threshold-disabled"
	snmCompressLow = "compression-threshold-too-low"
	snmEmpty       = "properties-empty"
	snmLink        = "properties-symlink"
	snmBom         = "properties-bom"
)

type OnlineModeFinding = auditFinding

type OnlineModeAudit struct {
	ServerDir string
	Findings  []OnlineModeFinding
}

func (a *OnlineModeAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, snmMaxFindings, OnlineModeFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *OnlineModeAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f OnlineModeFinding) bool { return f.Blocking })
}

func (a *OnlineModeAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *OnlineModeAudit) Describe() string {
	return describeReasonDetail("在线认证配置未发现风险", a.Findings, 12)
}

func snmReadProps(serverDir string, a *OnlineModeAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(snmMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(snmRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(snmLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, snmMaxFile)
	if err != nil {
		a.add(snmRead, err.Error(), true)
		return nil, false
	}
	text := string(data)
	if strings.HasPrefix(text, "\ufeff") {
		a.add(snmBom, "属性文件带 BOM 头，首键可能失效", false)
		text = strings.TrimPrefix(text, "\ufeff")
	}
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(snmEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}
