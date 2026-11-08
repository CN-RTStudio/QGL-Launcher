package main

// pathguard.go —— 路径归属（containment）判定的共享安全内核。
//
// 启动器会把大量“来自外部清单 / 压缩包 / 环境变量”的路径拼到真实文件系统上：
// 解压目标、natives 目录、libraries jar、以及最终要 exec 的 java 可执行文件。
// 历史上这些检查分散在各文件里、各写一份 filepath.Abs + HasPrefix，容易漏判
// 两类问题：
//   1. 词法逃逸：".."、盘符、相对路径拼出 root 之外（Zip Slip）；
//   2. 符号链接逃逸：词法上在 root 内，但其中某一级目录/文件是指向 root 之外
//      的符号链接 / junction（Windows），写入或执行会“顺着链接”落到外部。
//
// 这里提供唯一的判定实现：词法归属 PathWithinRoot，和解析真实路径后的归属
// ResolvedPathWithinRoot，供解压与可执行文件信任复用，配单元测试。

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// canonicalAbs 返回去掉结尾分隔符（根目录自身除外）的干净绝对路径，
// 保证 HasPrefix 比较不会被 "/a/b" 误判成 "/a/bc" 这类兄弟目录。
func canonicalAbs(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) {
		return "", os.ErrInvalid
	}
	a, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	// Windows 卷名大小写归一（C:\ 与 c:\）。
	if vol := filepath.VolumeName(a); vol != "" {
		a = strings.ToUpper(vol) + a[len(vol):]
	}
	return a, nil
}

// PathWithinRoot 做纯词法（不触碰文件系统）的归属判定：child 必须等于 root
// 或位于 root 之内。两者都会先转成干净绝对路径。
func PathWithinRoot(child, root string) bool {
	return pathWithinRootMode(child, root, runtime.GOOS == "windows")
}

func pathWithinRootMode(child, root string, fold bool) bool {
	absRoot, err := canonicalAbs(root)
	if err != nil {
		return false
	}
	absChild, err := canonicalAbs(child)
	if err != nil {
		return false
	}
	rootKey := pathCompareKey(absRoot, fold)
	childKey := pathCompareKey(absChild, fold)
	if childKey == rootKey {
		return true
	}
	return strings.HasPrefix(childKey, rootKey+string(os.PathSeparator))
}

func pathCompareKey(p string, fold bool) string {
	if fold {
		return strings.ToLower(p)
	}
	return p
}

// ResolvedPathWithinRoot 先解析 root 与 child 的真实路径（跟随符号链接 /
// junction），再判定真实 child 是否仍在真实 root 之内。
//
// 行为约定：
//   - root 必须已存在（要执行/写入的受信根目录必然存在），解析失败视为不通过；
//   - child 已存在时按真实路径判定，能挡住“链接落在 root 内、目标在 root 外”；
//   - child 尚不存在（如解压前预校验目标）时退回词法判定，但要求其父目录的
//     真实路径仍在 root 内，避免新建名本身借父目录链接逃逸。
//
// 返回归一化后的真实 child 路径（供调用方记录 / 使用）。
func ResolvedPathWithinRoot(child, root string) (string, bool) {
	return resolvedPathWithinRootMode(child, root, runtime.GOOS == "windows")
}

func resolvedPathWithinRootMode(child, root string, fold bool) (string, bool) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	realRoot, err = canonicalAbs(realRoot)
	if err != nil {
		return "", false
	}

	if _, statErr := os.Lstat(child); statErr == nil {
		realChild, err := filepath.EvalSymlinks(child)
		if err != nil {
			return "", false
		}
		realChild, err = canonicalAbs(realChild)
		if err != nil {
			return "", false
		}
		return realChild, pathWithinRootMode(realChild, realRoot, fold)
	}

	// child 尚不存在：用词法 child 与“已解析的真实父目录”双重确认。
	parent := filepath.Dir(child)
	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		// 父目录也不存在，无法用真实路径背书，退化为纯词法判定（保守但可用）。
		lexChild, e := canonicalAbs(child)
		if e != nil {
			return "", false
		}
		return lexChild, pathWithinRootMode(lexChild, realRoot, fold)
	}
	realParent, err = canonicalAbs(realParent)
	if err != nil {
		return "", false
	}
	if !pathWithinRootMode(realParent, realRoot, fold) {
		return "", false
	}
	lexChild, err := canonicalAbs(child)
	if err != nil {
		return "", false
	}
	return lexChild, pathWithinRootMode(lexChild, realRoot, fold)
}
