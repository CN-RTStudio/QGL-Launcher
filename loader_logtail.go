package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

const logViewMaxBytes int64 = 4 << 20

func readLogTail(path string, maxBytes int64) (string, bool, error) {
	if maxBytes <= 0 {
		return "", false, errors.New("readLogTail 必须指定正的体积上限")
	}
	bad, err := isSymlinkOrSpecial(path)
	if err != nil {
		return "", false, err
	}
	if bad {
		return "", false, fmt.Errorf("拒绝读取符号链接或非普通文件: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", false, err
	}
	size := info.Size()
	truncated := size > maxBytes
	if truncated {
		if _, err := f.Seek(size-maxBytes, io.SeekStart); err != nil {
			return "", false, err
		}
	}
	body, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return "", false, err
	}
	if truncated {
		if idx := bytes.IndexByte(body, '\n'); idx >= 0 {
			body = body[idx+1:]
		}
	}
	return string(body), truncated, nil
}
