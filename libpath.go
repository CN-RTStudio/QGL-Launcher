package main

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

var errUnsafeRelPath = errors.New("unsafe relative path")

func safeRelPath(root, rel string) (string, error) {
	if root == "" || rel == "" {
		return "", errUnsafeRelPath
	}
	candidate := strings.ReplaceAll(rel, "\\", "/")
	if strings.HasPrefix(candidate, "/") {
		return "", errUnsafeRelPath
	}
	if len(candidate) >= 2 && candidate[1] == ':' {
		return "", errUnsafeRelPath
	}
	if strings.HasPrefix(candidate, "//") {
		return "", errUnsafeRelPath
	}
	cleaned := path.Clean(candidate)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errUnsafeRelPath
	}
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", errUnsafeRelPath
		}
		for _, r := range seg {
			if r < 0x20 || r == 0x7F {
				return "", errUnsafeRelPath
			}
			if strings.ContainsRune(`<>:"|?*`, r) {
				return "", errUnsafeRelPath
			}
		}
	}
	full := filepath.Join(root, filepath.FromSlash(cleaned))
	if _, err := pathInsideRoot(root, full); err != nil {
		return "", errUnsafeRelPath
	}
	return full, nil
}

func isHexHash(s string) bool {
	if len(s) != 64 && len(s) != 40 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func validateVersionName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("非法版本名长度")
	}
	if strings.ContainsAny(name, `/\:*?"<>|`) || strings.Contains(name, "..") {
		return fmt.Errorf("非法版本名")
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("非法版本名")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7F {
			return fmt.Errorf("非法版本名")
		}
	}
	return nil
}
