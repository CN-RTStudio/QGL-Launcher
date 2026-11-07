package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	plaMaxFindings = 14
	plaMaxFile     = 16 * 1024 * 1024
	plaMaxPlayers  = 512
	plaMiss        = "playerdata-dir-missing"
	plaRead        = "playerdata-dir-unreadable"
	plaLink        = "playerdata-dir-symlink"
	plaFileMiss    = "playerdata-file-missing"
	plaFileLink    = "playerdata-file-symlink"
	plaFileEmpty   = "playerdata-file-empty"
	plaFileBig     = "playerdata-file-oversized"
	plaFileGzip    = "playerdata-file-not-gzip"
	plaNameForm    = "playerdata-name-malformed"
	plaTooMany     = "playerdata-count-high"
	plaBackup      = "playerdata-backup-residue"
)

var (
	plaUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.dat$`)
	plaBackupMark  = ".dat_old"
)

type PlyDataFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type PlyDataAudit struct {
	ServerDir string
	Files     int
	Findings  []PlyDataFinding
}

func (a *PlyDataAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= plaMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PlyDataFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PlyDataAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *PlyDataAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *PlyDataAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("playerdata 目录通过检查，共 %d 个存档文件", a.Files)
	}
	sorted := make([]PlyDataFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].File < sorted[j].File
	})
	parts := make([]string, 0, len(sorted))
	for i, f := range sorted {
		if i >= 8 {
			parts = append(parts, fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		parts = append(parts, f.Reason)
	}
	return strings.Join(parts, "；")
}

func plaGzipHeader(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	head := make([]byte, 2)
	if _, err := file.Read(head); err != nil {
		return false
	}
	return head[0] == 0x1f && head[1] == 0x8b
}

func AuditPlyDataFiles(serverDir string) *PlyDataAudit {
	a := &PlyDataAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("world/playerdata", plaMiss, "未配置服务器目录", false)
		return a
	}

	dirs := []string{
		filepath.Join(serverDir, "world", "playerdata"),
		filepath.Join(serverDir, "playerdata"),
	}
	var dir string
	for _, candidate := range dirs {
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			dir = candidate
			break
		}
	}
	if dir == "" {
		a.add("world/playerdata", plaMiss, "缺少玩家数据目录", false)
		return a
	}

	link, err := isSymlinkOrSpecial(dir)
	if err != nil {
		a.add("world/playerdata", plaRead, err.Error(), true)
		return a
	}
	if link {
		a.add("world/playerdata", plaLink, "玩家数据目录是符号链接或特殊文件", true)
		return a
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add("world/playerdata", plaRead, "无法读取玩家数据目录", true)
		return a
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, name)
		if strings.HasSuffix(name, plaBackupMark) {
			a.add(name, plaBackup, "遗留的旧存档副本可能携带过期权限数据", false)
			continue
		}
		if !strings.HasSuffix(name, ".dat") {
			continue
		}
		a.Files++
		if !plaUUIDPattern.MatchString(strings.ToLower(name)) {
			a.add(name, plaNameForm, "文件名不是标准 UUID.dat", false)
		}
		link, err := isSymlinkOrSpecial(path)
		if err != nil {
			a.add(name, plaFileMiss, err.Error(), true)
			continue
		}
		if link {
			a.add(name, plaFileLink, "存档文件是符号链接或特殊文件", true)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			a.add(name, plaFileMiss, "存档文件无法访问", true)
			continue
		}
		if info.Size() == 0 {
			a.add(name, plaFileEmpty, "存档文件为空", false)
			continue
		}
		if info.Size() > plaMaxFile {
			a.add(name, plaFileBig, fmt.Sprintf("存档文件 %d 字节超过上限 %d", info.Size(), int64(plaMaxFile)), false)
			continue
		}
		if !plaGzipHeader(path) {
			a.add(name, plaFileGzip, "存档文件缺少 gzip 魔数，可能被替换", true)
		}
	}

	if a.Files > plaMaxPlayers {
		a.add("world/playerdata", plaTooMany, fmt.Sprintf("存档文件数 %d 超过预期上限 %d", a.Files, plaMaxPlayers), false)
	}
	return a
}
