package main

import (
	"fmt"
	"strings"
)

const (
	worldReasonOK           = "ok"
	worldReasonUnsafeName   = "unsafe-name"
	worldReasonEscape       = "escape"
	worldReasonSymlink      = "symlink"
	worldReasonNotDirectory = "not-directory"
	worldMaxNameRunes       = 96
	worldProbeBytes         = 4 << 20
)

type WorldPathAudit struct {
	LevelName string
	Path      string
	Present   bool
	Symlink   bool
	Reason    string
	Warnings  []string
}

func (audit WorldPathAudit) Blocking() bool {
	switch audit.Reason {
	case worldReasonUnsafeName, worldReasonEscape, worldReasonSymlink, worldReasonNotDirectory:
		return true
	default:
		return false
	}
}

func (audit WorldPathAudit) Describe() string {
	switch audit.Reason {
	case worldReasonOK:
		return "世界目录位置校验通过"
	case worldReasonUnsafeName:
		return fmt.Sprintf("level-name 不是安全的单段目录名: %q", audit.LevelName)
	case worldReasonEscape:
		return "世界目录解析后位于服务器目录之外"
	case worldReasonSymlink:
		return "世界目录是符号链接，拒绝沿用该路径"
	case worldReasonNotDirectory:
		return "世界目录位置被非目录文件占用"
	default:
		return "世界目录位置未知"
	}
}

func safeWorldLevelName(name string) bool {
	if name == "" || len(name) > worldMaxNameRunes {
		return false
	}
	if strings.TrimSpace(name) != name {
		return false
	}
	if strings.HasPrefix(name, ".") || name == "-" {
		return false
	}
	if strings.ContainsAny(name, "/\\:") {
		return false
	}
	if strings.ContainsRune(name, 0) || containsControlByte(name) {
		return false
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	if isReservedDeviceName(stemOfName(name)) {
		return false
	}
	return true
}
