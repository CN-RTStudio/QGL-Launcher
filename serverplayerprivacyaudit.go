package main

import (
	"os"
	"path/filepath"
	"regexp"
)

const (
	ppReasonOK            = "ok"
	ppReasonMissing       = "missing"
	ppReasonSymlink       = "symlink"
	ppReasonTooLarge      = "too-large"
	ppReasonWorldWritable = "world-writable"
	ppReasonWorldReadable = "world-readable"
	ppReasonUnreadable    = "unreadable"
	ppReasonMalformedJSON = "malformed-json"
	ppReasonOverflow      = "entry-overflow"
	ppReasonStaleEntry    = "stale-entry"
	ppReasonDuplicateUUID = "duplicate-uuid"
	ppReasonBadName       = "bad-player-name"
	ppReasonOpLevel       = "full-op-level"
	ppReasonBypassLimit   = "bypass-player-limit"
	ppReasonBannedAll     = "banned-all-addresses"
	ppReasonInvalidIP     = "invalid-ip"
	ppReasonOnlineMode    = "offline-mode"
	ppReasonLogIPLeak     = "log-ip-leak"

	ppMaxJSONBytes  = 1 << 20
	ppMaxLogBytes   = 8 << 20
	ppMaxEntries    = 5000
	ppMaxStaleDays  = 500
	ppMaxFindings   = 48
	ppMaxLogIPCount = 0
)

var (
	ppUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ppIPPattern   = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	ppLogIP       = regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}`)
	ppNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,16}$`)
)

type ppUserEntry struct {
	Name      string `json:"name"`
	UUID      string `json:"uuid"`
	ExpiresOn string `json:"expiresOn"`
}

type ppBanEntry struct {
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
}

func ppLoadJSON(a *PlayerPrivacyAudit, dir, name string) []byte {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			a.add(name, ppReasonMissing, "缺少玩家数据文件", false)
		}
		return nil
	}
	a.Files = append(a.Files, name)
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(name, ppReasonSymlink, "玩家数据文件是符号链接", true)
		return nil
	}
	if info.Size() > ppMaxJSONBytes {
		a.add(name, ppReasonTooLarge, "玩家数据文件超过体积预算", true)
		return nil
	}
	if info.Mode().Perm()&0o022 != 0 {
		a.add(name, ppReasonWorldWritable, "玩家数据文件可被其他用户改写", true)
	}
	if info.Mode().Perm()&0o004 != 0 {
		a.add(name, ppReasonWorldReadable, "玩家数据文件对其他用户可读", false)
	}
	data, readErr := readBoundedFile(path, ppMaxJSONBytes)
	if readErr != nil {
		a.add(name, ppReasonUnreadable, "玩家数据文件不可读", true)
		return nil
	}
	return data
}
