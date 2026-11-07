package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	rgnMaxFindings = 14
	rgnMaxFile     = 64 * 1024 * 1024
	rgnSector      = 4096
	rgnMaxFiles    = 4096
	rgnMiss        = "region-dir-missing"
	rgnRead        = "region-dir-unreadable"
	rgnLink        = "region-dir-symlink"
	rgnFileMiss    = "region-file-missing"
	rgnFileLink    = "region-file-symlink"
	rgnFileEmpty   = "region-file-empty"
	rgnFileAligned = "region-file-unaligned"
	rgnFileBig     = "region-file-oversized"
	rgnHeaderShort = "region-file-header-short"
	rgnHeaderMagic = "region-file-header-flags"
	rgnNameForm    = "region-file-name-malformed"
	rgnTooMany     = "region-file-count-high"
)

type RgnFileFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type RgnFileAudit struct {
	ServerDir string
	Files     int
	Findings  []RgnFileFinding
}

func (a *RgnFileAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= rgnMaxFindings {
		return
	}
	a.Findings = append(a.Findings, RgnFileFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *RgnFileAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *RgnFileAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *RgnFileAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("region 目录通过检查，共 %d 个区域文件", a.Files)
	}
	sorted := make([]RgnFileFinding, len(a.Findings))
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

func rgnHeaderFlags(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	head := make([]byte, 4)
	n, err := file.Read(head)
	if err != nil && n < len(head) {
		return n, nil
	}
	if n < len(head) {
		return n, nil
	}
	// 首扇区为 chunk 偏移表，前 4 字节须全为 0，合法标志只可能出现在 chunk 自身。
	if head[0] == 0 && head[1] == 0 && head[2] == 0 && head[3] == 0 {
		return 0, nil
	}
	return -1, nil
}

func AuditRgnFiles(serverDir string) *RgnFileAudit {
	a := &RgnFileAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("world/region", rgnMiss, "未配置服务器目录", false)
		return a
	}

	dirs := []string{
		filepath.Join(serverDir, "world", "region"),
		filepath.Join(serverDir, "region"),
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
		a.add("world/region", rgnMiss, "缺少区域文件目录", false)
		return a
	}

	link, err := isSymlinkOrSpecial(dir)
	if err != nil {
		a.add("world/region", rgnRead, err.Error(), true)
		return a
	}
	if link {
		a.add("world/region", rgnLink, "区域目录是符号链接或特殊文件", true)
		return a
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add("world/region", rgnRead, "无法读取区域目录", true)
		return a
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(name), ".mca") {
			continue
		}
		a.Files++
		if len(name) != len("r.1.2.mca") {
			a.add(name, rgnNameForm, "文件名不符合 r.<x>.<z>.mca 形式", false)
		}
		path := filepath.Join(dir, name)
		link, err := isSymlinkOrSpecial(path)
		if err != nil {
			a.add(name, rgnFileMiss, err.Error(), true)
			continue
		}
		if link {
			a.add(name, rgnFileLink, "区域文件是符号链接或特殊文件", true)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			a.add(name, rgnFileMiss, "区域文件无法访问", true)
			continue
		}
		if info.Size() == 0 {
			a.add(name, rgnFileEmpty, "区域文件为空", true)
			continue
		}
		if info.Size() < rgnSector {
			a.add(name, rgnHeaderShort, "区域文件不足一个扇区，头部不完整", true)
			continue
		}
		if info.Size()%rgnSector != 0 {
			a.add(name, rgnFileAligned, fmt.Sprintf("区域文件 %d 字节未按 %d 扇区对齐", info.Size(), rgnSector), false)
		}
		if info.Size() > rgnMaxFile {
			a.add(name, rgnFileBig, fmt.Sprintf("区域文件 %d 字节超过上限 %d", info.Size(), int64(rgnMaxFile)), false)
		}
		flags, err := rgnHeaderFlags(path)
		if err != nil {
			a.add(name, rgnRead, err.Error(), true)
			continue
		}
		if flags != 0 {
			a.add(name, rgnHeaderMagic, "首扇区偏移表非零，头部可能被篡改", false)
		}
	}

	if a.Files > rgnMaxFiles {
		a.add("world/region", rgnTooMany, fmt.Sprintf("区域文件数 %d 超过上限 %d", a.Files, rgnMaxFiles), false)
	}
	return a
}
