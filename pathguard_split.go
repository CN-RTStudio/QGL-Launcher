package main

import (
	"os"
	"path/filepath"
	"runtime"
)

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
