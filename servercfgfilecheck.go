package main

import (
	"fmt"
	"os"
	"path/filepath"
)

type cfgFileReasons struct {
	Missing       string
	Unreadable    string
	Symlink       string
	TooLarge      string
	WorldWritable string
	WorldReadable string
}

type cfgFileLabels struct {
	Noun      string
	SizeLabel string
}

func checkServerCfgFile(dir, rel string, maxBytes int64, reasons cfgFileReasons, labels cfgFileLabels, add func(reason, detail string, blocking bool)) bool {
	path := filepath.Join(dir, filepath.FromSlash(rel))
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			add(reasons.Missing, labels.Noun+"不存在", false)
		} else {
			add(reasons.Unreadable, err.Error(), false)
		}
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		add(reasons.Symlink, labels.Noun+"是符号链接", true)
		return false
	}
	if !info.Mode().IsRegular() {
		add(reasons.Unreadable, labels.Noun+"不是普通文件", true)
		return false
	}
	if info.Size() > maxBytes {
		add(reasons.TooLarge, fmt.Sprintf("%s %d 字节", labels.SizeLabel, info.Size()), true)
		return false
	}
	if info.Mode().Perm()&0o022 != 0 {
		add(reasons.WorldWritable, fmt.Sprintf("权限 %#o 允许他人写入", info.Mode().Perm()), true)
	}
	if info.Mode().Perm()&0o004 != 0 {
		add(reasons.WorldReadable, fmt.Sprintf("权限 %#o 允许他人读取", info.Mode().Perm()), false)
	}
	return true
}
