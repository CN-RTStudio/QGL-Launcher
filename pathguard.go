package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

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

func safeRelChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	}
	switch r {
	case '.', '_', '-', '+', '~':
		return true
	}
	return false
}
func validateSafeSegment(seg string) bool {
	if seg == "" || seg == "." || seg == ".." {
		return false
	}
	for _, r := range seg {
		if !safeRelChar(r) {
			return false
		}
	}
	// Windows 资源管理器 / Win32 会吞掉结尾的点和空格，可能造成同名绕过。
	if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
		return false
	}
	upper := strings.ToUpper(seg)
	if dot := strings.IndexByte(upper, '.'); dot >= 0 {
		upper = upper[:dot]
	}
	switch upper {
	case "CON", "PRN", "AUX", "NUL":
		return false
	}
	if len(upper) == 4 {
		p := upper[:3]
		if (p == "COM" || p == "LPT") && upper[3] >= '1' && upper[3] <= '9' {
			return false
		}
	}
	return true
}
