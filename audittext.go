package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func loadServerText(root, rel string, maxBytes int64, add func(file, reason, detail string, blocking bool)) (string, bool) {
	path := filepath.Join(root, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		add(rel, secReasonSymlink, "配置文件为符号链接或特殊文件", true)
		return "", false
	}
	data, err := readBoundedFile(path, maxBytes)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return "", false
		}
		if errors.Is(err, errLocalFileTooLarge) {
			add(rel, secReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", maxBytes), true)
			return "", false
		}
		add(rel, secReasonUnread, "配置文件不可读", false)
		return "", false
	}
	return string(data), true
}
