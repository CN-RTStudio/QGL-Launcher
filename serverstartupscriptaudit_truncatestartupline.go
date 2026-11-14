package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func truncateStartupLine(line string) string {
	line = strings.TrimSpace(line)
	clean := sanitizeLogLine(line)
	runes := []rune(clean)
	if len(runes) <= startupTruncatedDetailRunes {
		return clean
	}
	return string(runes[:startupTruncatedDetailRunes]) + "..."
}

func truncateToRuneBoundary(data []byte, max int) string {
	if len(data) <= max {
		return string(data)
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(data[cut]) {
		cut--
	}
	return string(data[:cut])
}

func readStartupScript(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("脚本是符号链接: %s", filepath.Base(path))
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("脚本不是常规文件: %s", filepath.Base(path))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, startupMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > startupMaxBytes {
		return nil, fmt.Errorf("脚本超过 %d 字节", startupMaxBytes)
	}
	return data, nil
}
