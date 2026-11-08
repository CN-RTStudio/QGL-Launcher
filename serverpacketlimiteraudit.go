package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	pklMaxFindings        = 48
	pklMaxYAML            = 512 * 1024
	pklMaxRate            = 600
	pklMaxAutoSave        = 24
	pklMaxKickMessage     = 256
	pklReasonOK           = "ok"
	pklReasonMissing      = "missing"
	pklReasonSymlink      = "symlink"
	pklReasonTooLarge     = "too-large"
	pklReasonUnreadable   = "unreadable"
	pklReasonBadConfig    = "bad-config"
	pklReasonBadValue     = "bad-value"
	pklReasonLimiterOff   = "limiter-disabled"
	pklReasonLimiterLoose = "limiter-loose"
	pklReasonKickMessage  = "bad-kick-message"
	pklReasonXrayOff      = "anti-xray-disabled"
	pklReasonXrayEngine   = "bad-engine-mode"
	pklReasonXrayEmpty    = "empty-block-list"
	pklReasonAutoSave     = "auto-save-burst"
)

type PacketLimiterFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type PacketLimiterAudit struct {
	ServerDir string
	Limits    int
	Findings  []PacketLimiterFinding
}

func (a *PacketLimiterAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= pklMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PacketLimiterFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PacketLimiterAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PacketLimiterFinding) bool { return f.Blocking })
}

func (a *PacketLimiterAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if f.Reason != pklReasonOK && !f.Blocking {
			return true
		}
	}
	return false
}

func (a *PacketLimiterAudit) Describe() string {
	return describeFindings(a.Findings, func(f PacketLimiterFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func pklLoadFlat(a *PacketLimiterAudit, root, rel string) map[string]string {
	path := filepath.Join(root, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, pklReasonSymlink, "配置文件为符号链接或特殊文件", true)
		return nil
	}
	data, err := readBoundedFile(path, pklMaxYAML)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return nil
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, pklReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", pklMaxYAML), true)
			return nil
		}
		a.add(rel, pklReasonUnreadable, "配置文件不可读", false)
		return nil
	}
	text := string(data)
	flat := cfgFlattenYAML(text)
	if len(flat) == 0 && strings.TrimSpace(text) != "" {
		a.add(rel, pklReasonBadConfig, "配置文件未解析出任何键值", false)
	}
	return flat
}

func pklBool(a *PacketLimiterAudit, file, label, value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	}
	a.add(file, pklReasonBadValue, label+" 不是合法布尔值: "+value, false)
	return false, false
}
