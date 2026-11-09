package main

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
