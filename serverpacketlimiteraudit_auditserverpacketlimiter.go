package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func AuditServerPacketLimiter(serverDir string) *PacketLimiterAudit {
	a := &PacketLimiterAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", pklReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", pklReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", pklReasonMissing, "服务器目录不存在", false)
		return a
	}
	flat := pklLoadFlat(a, serverDir, "config/paper-global.yml")
	if flat == nil {
		a.add(".", pklReasonMissing, "未发现 paper-global.yml", false)
		return a
	}
	pklCheckLimiter(a, flat)
	pklCheckAntiXray(a, flat)
	pklCheckChunkLoading(a, flat)
	pklCheckOverrides(a, flat)
	return a
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
