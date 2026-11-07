package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	sldMaxFindings = 24
	sldMaxFile     = 64 * 1024 * 1024
	sldReasonMiss  = "missing"
	sldReasonLink  = "symlink"
	sldReasonLarge = "too-large"
	sldReasonRead  = "unreadable"
	sldReasonMagic = "invalid-gzip"
	sldReasonNBT   = "invalid-nbt"
	sldReasonName  = "unsafe-level-name"
	sldReasonAllow = "commands-allowed"
	sldReasonHard  = "hardcore-world"
	sldReasonSeed  = "seed-embedded"
	sldReasonGen   = "unknown-generator"
)

type LevelDataFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type LevelDataAudit struct {
	ServerDir string
	Findings  []LevelDataFinding
}

func (a *LevelDataAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= sldMaxFindings {
		return
	}
	a.Findings = append(a.Findings, LevelDataFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *LevelDataAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *LevelDataAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *LevelDataAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "level.dat 未发现风险"
	}
	sorted := make([]LevelDataFinding, len(a.Findings))
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

func sldPrintableString(data []byte, tag string) string {
	idx := bytes.Index(data, []byte(tag))
	if idx < 0 || idx+len(tag)+4 > len(data) {
		return ""
	}
	rest := data[idx+len(tag):]
	if rest[0] != 0x08 {
		return ""
	}
	valueLen := int(rest[1])<<8 | int(rest[2])
	if valueLen <= 0 || valueLen > 128 || 3+valueLen > len(rest) {
		return ""
	}
	return string(rest[3 : 3+valueLen])
}

func AuditServerLevelData(serverDir string) *LevelDataAudit {
	a := &LevelDataAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("world/level.dat", sldReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "world/level.dat"
	path := filepath.Join(serverDir, filepath.FromSlash(rel))
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, sldReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, sldReasonLink, "存档元数据是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, sldReasonMiss, "未找到 level.dat", false)
		return a
	}
	info, err := os.Stat(path)
	if err != nil {
		a.add(rel, sldReasonRead, err.Error(), true)
		return a
	}
	if info.Size() > sldMaxFile {
		a.add(rel, sldReasonLarge, fmt.Sprintf("文件 %d 字节", info.Size()), true)
		return a
	}
	data, err := os.ReadFile(path)
	if err != nil {
		a.add(rel, sldReasonRead, err.Error(), true)
		return a
	}
	if len(data) < 8 || !bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		a.add(rel, sldReasonMagic, "缺少 gzip 头", true)
		return a
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		a.add(rel, sldReasonNBT, "gzip 解压失败", true)
		return a
	}
	inner, err := io.ReadAll(io.LimitReader(zr, sldMaxFile+1))
	zr.Close()
	if err != nil {
		a.add(rel, sldReasonNBT, "gzip 流损坏", true)
		return a
	}
	if int64(len(inner)) > sldMaxFile {
		a.add(rel, sldReasonLarge, "解压后超过上限", true)
		return a
	}
	data = inner
	if !bytes.Contains(data, []byte("Data")) {
		a.add(rel, sldReasonNBT, "NBT 结构中缺少 Data 根", true)
	}
	if !bytes.Contains(data, []byte("LevelName")) {
		a.add(rel, sldReasonNBT, "缺少 LevelName 字段", false)
	}
	name := sldPrintableString(data, "LevelName")
	if name != "" && cfgHasControlChars(name) {
		a.add(rel, sldReasonName, "世界名含控制字符", true)
	}
	if bytes.Contains(data, []byte("allowCommands")) && bytes.Contains(data, []byte{0x00, 0x01, 0x01}) {
		a.add(rel, sldReasonAllow, "存档默认开启命令", false)
	}
	if bytes.Contains(data, []byte("hardcore")) && bytes.Contains(data, []byte{0x00, 0x01, 0x01}) {
		a.add(rel, sldReasonHard, "硬核模式存档", false)
	}
	if bytes.Contains(data, []byte("generatorName")) && !bytes.Contains(data, []byte("default")) && !bytes.Contains(data, []byte("flat")) && !bytes.Contains(data, []byte("largeBiomes")) {
		a.add(rel, sldReasonGen, "自定义地形生成器", false)
	}
	if bytes.Contains(data, []byte("worldGenSettings")) && !bytes.Contains(data, []byte("seed")) {
		a.add(rel, sldReasonSeed, "世界生成设置缺少种子字段", false)
	}
	return a
}
