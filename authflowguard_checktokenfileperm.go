package main

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func CheckTokenFilePerm(path string) (bool, string) {
	if runtime.GOOS == "windows" {
		return true, "windows-acl-out-of-scope"
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, "cannot stat token file: " + err.Error()
	}
	perm := info.Mode().Perm()
	if perm&0o077 != 0 {
		return false, "token file permissions too broad: " + strconv.FormatUint(uint64(perm), 8)
	}
	return true, "perm-ok"
}

// SummarizeAuthVerdict 把校验结论压成简短可读文本。
func SummarizeAuthVerdict(v AuthVerdict) string {
	if v.Ok {
		return "auth check ok"
	}
	return "auth check FAILED: " + strings.Join(v.Reasons, "; ")
}

// UnwrapAuthError 把 AuthVerdict 转成标准 error（用于需要 error 的调用点）。
func UnwrapAuthError(v AuthVerdict) error {
	if v.Ok {
		return nil
	}
	return errors.New(SummarizeAuthVerdict(v))
}
