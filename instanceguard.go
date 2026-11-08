package main

// instanceguard.go —— 游戏实例目录安全审计内核。
//
// 背景：
//   启动器管理的每个游戏实例（.minecraft 目录）会经手大量第三方内容：mod、资源包、
//   光影、版本 jar、native 库。这些内容来源混杂（在线下载、压缩包解压、用户手拖、
//   别的启动器迁移），一旦其中出现“符号链接指向实例根外”的条目，启动器后续的清理、
//   备份、哈希校验等递归操作就会顺着链接读写实例外的任意文件（链接逃逸），这是
//   一类典型且真实的本地安全面；同时 versions/ 子目录若可互相覆盖或越界引用，版本
//   隔离就会被打破，恶意版本可顶替合法版本被加载。
//
// 设计要点：
//   - 全部只读，不修改实例内任何文件；审计失败只上报，绝不自动删改；
//   - ValidateInstanceRoot 对实例根路径做格式净化：非空、限长、拒绝控制字符、
//     拒绝 UNC/相对路径/危险目录前缀，解析为绝对路径；
//   - ScanInstanceSymlinks 用 os.Lstat（不跟随）递归发现符号链接，解析目标后用
//     filepath.Rel 判定是否逃逸实例根——逃逸即记入高危列表；目录递归有深度与
//     条目数上界，防符号链接/目录结构炸弹拖死审计；
//   - CheckVersionIsolation 校验 versions/ 下每个子目录名都是安全组件名，且
//     versions/<id>/ 内出现的文件不得是符号链接、不得指向 versions/<other>/
//     （跨版本引用即判越界）；libraries/ 同理只做组件名校验；
//   - 汇总结果四类：逃逸链接（最高危）、版本越界（高危）、异常条目（超长路径 /
//     非普通文件计数）、结构一致；只供上报与审计事件，不自动处置。

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// InstanceLimits 限定实例审计的扫描边界，全部带默认值，防“恶意塞满目录”类本地 DoS。
type InstanceLimits struct {
	MaxRootPathRunes  int // 实例根路径最大字符数
	MaxComponentRunes int // 单个子目录/文件名字符数上限
	MaxWalkDepth      int // 递归扫描最大深度
	MaxEntries        int // 递归扫描条目总数上限
	MaxSymlinks       int // 记录符号链接条目的上限
}

func (l *InstanceLimits) withDefaults() InstanceLimits {
	if l == nil {
		l = &InstanceLimits{}
	}
	out := *l
	if out.MaxRootPathRunes <= 0 {
		out.MaxRootPathRunes = 4096
	}
	if out.MaxComponentRunes <= 0 {
		out.MaxComponentRunes = 255
	}
	if out.MaxWalkDepth <= 0 {
		out.MaxWalkDepth = 12
	}
	if out.MaxEntries <= 0 {
		out.MaxEntries = 50000
	}
	if out.MaxSymlinks <= 0 {
		out.MaxSymlinks = 4096
	}
	return out
}

// InstanceVerdict 是一次实例审计的结构化结论。
type InstanceVerdict struct {
	Ok              bool
	Root            string
	EscapeLinks     []string // 逃逸实例根的符号链接（实例内相对路径）
	CrossVersionRef []string // 指向其它版本的越界引用（相对路径）
	BadComponents   []string // 含非法字符/超长的目录名（相对路径）
	NonRegularCount int
	EntryCount      int
	Error           string
}

// ValidateInstanceRoot 校验实例根路径的格式与安全性，返回净化后的绝对路径。
func ValidateInstanceRoot(root string, lim InstanceLimits) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("instance root is empty")
	}
	if len([]rune(root)) > lim.MaxRootPathRunes {
		return "", errors.New("instance root path too long")
	}
	if hasControlCharStr(root) {
		return "", errors.New("instance root contains control characters")
	}
	if strings.HasPrefix(root, `\\`) || strings.HasPrefix(root, `//`) {
		return "", errors.New("instance root must not be a UNC path")
	}
	vol := filepath.VolumeName(root)
	if vol == "" && !filepath.IsAbs(root) {
		return "", errors.New("instance root must be absolute")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	clean := filepath.Clean(abs)
	if clean != abs {
		// 含 . / .. 的路径不允许直接使用，调用方应先净化
		return "", errors.New("instance root must be already normalized")
	}
	return clean, nil
}

// instanceScanner 在单个实例根内做有界递归扫描。
type instanceScanner struct {
	lim        InstanceLimits
	rootAbs    string
	escape     []string
	crossRef   []string
	badComp    []string
	nonRegular int
	entries    int
	overflow   bool
}

// validateComponent 复用了全局 sanitizePathComponent 的语义，额外叠加字符数上限。
func validateComponent(name string, lim InstanceLimits) bool {
	if len([]rune(name)) > lim.MaxComponentRunes {
		return false
	}
	return sanitizePathComponent(name) == nil
}

// walkDir 递归扫描；深度与条目数受 InstanceLimits 约束。
func (s *instanceScanner) walkDir(dir string, depth int, rel string) {
	if s.overflow || depth > s.lim.MaxWalkDepth {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		s.overflow = true
		return
	}
	for _, e := range entries {
		if s.entries >= s.lim.MaxEntries {
			s.overflow = true
			return
		}
		s.entries++
		name := e.Name()
		childRel := name
		if rel != "" {
			childRel = rel + "/" + name
		}
		if !validateComponent(name, s.lim) {
			s.badComp = append(s.badComp, childRel)
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 {
			s.checkSymlink(dir, name, childRel)
			continue
		}
		if !mode.IsRegular() {
			s.nonRegular++
			continue
		}
		if e.IsDir() {
			s.walkDir(filepath.Join(dir, name), depth+1, childRel)
		}
	}
}

// checkSymlink 判定一个符号链接是否逃逸实例根，以及是否跨版本引用。
func (s *instanceScanner) checkSymlink(dir, name, childRel string) {
	full := filepath.Join(dir, name)
	target, err := os.Readlink(full)
	if err != nil {
		return
	}
	// 解析相对目标：先按链接所在目录解析为绝对路径再判定
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(dir, target)
	}
	rel, err := filepath.Rel(s.rootAbs, resolved)
	if err != nil {
		s.escape = append(s.escape, childRel)
		return
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		s.escape = append(s.escape, childRel)
		return
	}
	// 跨版本引用：versions/<a>/... -> versions/<b>/...
	if strings.HasPrefix(childRel, "versions/") && strings.Contains(childRel, "/") {
		parts := strings.SplitN(rel, string(filepath.Separator), 3)
		if len(parts) >= 2 && parts[0] == "versions" && parts[1] != "" {
			childParts := strings.SplitN(childRel, "/", 3)
			if len(childParts) >= 2 && childParts[1] != parts[1] {
				s.crossRef = append(s.crossRef, childRel)
			}
		}
	}
}

// AuditInstance 对实例根做一次完整安全审计。
func AuditInstance(root string, lim InstanceLimits) InstanceVerdict {
	v := InstanceVerdict{Ok: true, Root: root}
	d := lim.withDefaults()
	abs, err := ValidateInstanceRoot(root, d)
	if err != nil {
		v.Ok = false
		v.Error = err.Error()
		return v
	}
	if _, err := os.Stat(abs); err != nil {
		v.Ok = false
		v.Error = "instance root not accessible: " + err.Error()
		return v
	}
	sc := &instanceScanner{lim: d, rootAbs: abs}
	sc.walkDir(abs, 0, "")
	v.EscapeLinks = sc.escape
	v.CrossVersionRef = sc.crossRef
	v.BadComponents = sc.badComp
	v.NonRegularCount = sc.nonRegular
	v.EntryCount = sc.entries
	if sc.overflow {
		v.Ok = false
		v.Error = "scan overflowed configured limits"
		return v
	}
	sortStrings(v.EscapeLinks)
	sortStrings(v.CrossVersionRef)
	sortStrings(v.BadComponents)
	if len(v.EscapeLinks) > 0 || len(v.CrossVersionRef) > 0 || len(v.BadComponents) > 0 {
		v.Ok = false
	}
	if len(v.EscapeLinks) > d.MaxSymlinks {
		v.EscapeLinks = v.EscapeLinks[:d.MaxSymlinks]
	}
	return v
}

// CheckVersionIsolation 独立校验 versions/ 与 libraries/ 目录的组件名合法性，
// 并确认 versions 下不存在符号链接（版本目录必须真实存在，不允许链接替身）。
func CheckVersionIsolation(root string, lim InstanceLimits) InstanceVerdict {
	v := InstanceVerdict{Ok: true, Root: root}
	d := lim.withDefaults()
	abs, err := ValidateInstanceRoot(root, d)
	if err != nil {
		v.Ok = false
		v.Error = err.Error()
		return v
	}
	for _, sub := range []string{"versions", "libraries"} {
		dir := filepath.Join(abs, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !validateComponent(e.Name(), d) {
				v.BadComponents = append(v.BadComponents, sub+"/"+e.Name())
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				v.CrossVersionRef = append(v.CrossVersionRef, sub+"/"+e.Name())
			}
		}
	}
	sortStrings(v.BadComponents)
	sortStrings(v.CrossVersionRef)
	if len(v.BadComponents) > 0 || len(v.CrossVersionRef) > 0 {
		v.Ok = false
	}
	return v
}

// SummarizeInstanceAudit 把审计结论压成简短的可读文本（用于日志与事件落盘）。
func SummarizeInstanceAudit(v InstanceVerdict) string {
	var b strings.Builder
	if v.Ok {
		b.WriteString("instance audit ok")
	} else {
		b.WriteString("instance audit FAILED")
	}
	b.WriteString(" (root=" + v.Root + ", entries=" + strconv.Itoa(v.EntryCount) + ")")
	if len(v.EscapeLinks) > 0 {
		b.WriteString(", escapeLinks=" + strconv.Itoa(len(v.EscapeLinks)))
	}
	if len(v.CrossVersionRef) > 0 {
		b.WriteString(", crossVersion=" + strconv.Itoa(len(v.CrossVersionRef)))
	}
	if len(v.BadComponents) > 0 {
		b.WriteString(", badComponents=" + strconv.Itoa(len(v.BadComponents)))
	}
	if v.NonRegularCount > 0 {
		b.WriteString(", nonRegular=" + strconv.Itoa(v.NonRegularCount))
	}
	if v.Error != "" {
		b.WriteString(", error=" + v.Error)
	}
	return b.String()
}
