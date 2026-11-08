package main

// worldmeta：世界目录守卫。
//
// 场景：选择存档 / 制作备份 / 上传世界时，启动器会遍历 saves/ 下的世界目录。
// 恶意世界目录（名称含控制字符或 "../"、带符号链接、缺 level.dat 伪装）会让
// 启动器把备份或上传目标指向启动器目录之外的任意位置。本模块在涉及世界目录
// 的任何操作前做结构校验：
//   - 世界目录名：单段、非空、无 .. / . / 反斜杠 / 控制字符 / 绝对前缀，长度有界；
//   - 世界目录必须含 level.dat（或 level.dat_old），且这些文件非符号链接；
//   - level.dat 大小与 NBT 魔数有界（防畸形文件拖慢解析 / 伪装文件）；
//   - 常见子目录（region / playerdata / advancements / stats / datapacks）
//     若存在则必须是真实目录且无符号链接。

import (
	"os"
	"path/filepath"
	"strings"
)

// WorldLimits 世界目录守卫的量化边界。
type WorldLimits struct {
	MaxNameLen     int   // 目录名长度上限
	MaxLevelDat    int64 // level.dat 大小上限
	RequireNoLink  bool  // 拒绝符号链接
}

func defaultWorldLimits() WorldLimits {
	return WorldLimits{MaxNameLen: 255, MaxLevelDat: 64 << 20, RequireNoLink: true}
}

const (
	wmNbtTagCompound = 0x0a // NBT TAG_Compound 魔数（gzip 内或裸）
	wmNbtGzipMagic1  = 0x1f // gzip 魔数
	wmNbtGzipMagic2  = 0x8b
)

type worldVerdict struct {
	OK      bool
	Reason  string
	HasBack bool // 是否存在 level.dat_old（回退可用）
}

// ValidateWorldName 校验世界目录名（单段）。
func ValidateWorldName(name string, lim WorldLimits) string {
	if lim.MaxNameLen == 0 {
		lim = defaultWorldLimits()
	}
	if name == "" {
		return "empty"
	}
	if len(name) > lim.MaxNameLen {
		return "too-long"
	}
	if strings.HasPrefix(name, "/") || (len(name) > 1 && name[1] == ':') {
		return "absolute"
	}
	if strings.ContainsAny(name, "/\\") {
		return "separator"
	}
	if strings.Contains(name, "..") {
		return "dotdot"
	}
	if hasControlCharStr(name) {
		return "control-char"
	}
	return ""
}

// probeLevelDat 探测 level.dat：存在、非符号链接、大小有界、NBT/gzip 魔数合理。
func probeLevelDat(p string, lim WorldLimits) (exists bool, reason string) {
	fi, err := os.Lstat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return false, ""
		}
		return false, "lstat-fail"
	}
	if lim.RequireNoLink && fi.Mode()&os.ModeSymlink != 0 {
		return false, "symlink"
	}
	if fi.IsDir() {
		return false, "is-dir"
	}
	if fi.Size() > lim.MaxLevelDat {
		return false, "too-large"
	}
	if fi.Size() < 4 {
		return false, "too-small"
	}
	// 魔数探测：gzip 头或裸 NBT 复合标签
	f, err := os.Open(p)
	if err != nil {
		return false, "open-fail"
	}
	defer f.Close()
	buf := make([]byte, 3)
	if _, err := f.Read(buf); err != nil {
		return false, "read-fail"
	}
	magicOK := (buf[0] == wmNbtGzipMagic1 && buf[1] == wmNbtGzipMagic2) ||
		(buf[0] == wmNbtTagCompound)
	if !magicOK {
		return false, "magic"
	}
	return true, ""
}

// ValidateWorldDir 校验一个世界目录整体。
func ValidateWorldDir(dir string, lim WorldLimits) worldVerdict {
	if lim.MaxNameLen == 0 {
		lim = defaultWorldLimits()
	}
	base := filepath.Base(dir)
	if r := ValidateWorldName(base, lim); r != "" {
		return worldVerdict{OK: false, Reason: "name:" + r}
	}
	if lim.RequireNoLink {
		fi, err := os.Lstat(dir)
		if err != nil {
			return worldVerdict{OK: false, Reason: "lstat-fail"}
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return worldVerdict{OK: false, Reason: "dir-symlink"}
		}
	}
	datExists, datReason := probeLevelDat(filepath.Join(dir, "level.dat"), lim)
	if !datExists {
		// 回退检查 level.dat_old
		oldExists, oldReason := probeLevelDat(filepath.Join(dir, "level.dat_old"), lim)
		if !oldExists {
			reason := "level-dat-missing"
			if oldReason != "" {
				reason = "level-dat-old:" + oldReason
			} else if datReason != "" {
				reason = "level-dat:" + datReason
			}
			return worldVerdict{OK: false, Reason: reason}
		}
		return worldVerdict{OK: true, HasBack: true}
	}
	if datReason != "" {
		return worldVerdict{OK: false, Reason: "level-dat:" + datReason}
	}
	// 常见子目录校验
	for _, sub := range []string{"region", "playerdata", "advancements", "stats", "datapacks", "entities"} {
		p := filepath.Join(dir, sub)
		fi, err := os.Lstat(p)
		if err != nil {
			continue // 可选目录
		}
		if lim.RequireNoLink && fi.Mode()&os.ModeSymlink != 0 {
			return worldVerdict{OK: false, Reason: "sub-symlink:" + sub}
		}
		if !fi.IsDir() {
			return worldVerdict{OK: false, Reason: "sub-not-dir:" + sub}
		}
	}
	return worldVerdict{OK: true}
}

// ScanSavesDir 扫描 saves/ 目录，逐个校验世界并汇总 bad 列表。
func ScanSavesDir(savesDir string, lim WorldLimits) (ok bool, bad []string) {
	if lim.MaxNameLen == 0 {
		lim = defaultWorldLimits()
	}
	bad = []string{}
	entries, err := os.ReadDir(savesDir)
	if err != nil {
		return false, []string{"readdir-fail"}
	}
	for _, e := range entries {
		if !e.IsDir() {
			if e.Type()&os.ModeSymlink != 0 && lim.RequireNoLink {
				bad = append(bad, "symlink:"+e.Name())
			}
			continue
		}
		full := filepath.Join(savesDir, e.Name())
		vd := ValidateWorldDir(full, lim)
		if !vd.OK {
			bad = append(bad, e.Name()+":"+vd.Reason)
		}
	}
	return len(bad) == 0, bad
}

// SummarizeWorldVerdict 压成一行。
func SummarizeWorldVerdict(vd worldVerdict) string {
	if vd.OK {
		if vd.HasBack {
			return "world ok (backup level.dat_old)"
		}
		return "world ok"
	}
	return "world bad " + vd.Reason
}
