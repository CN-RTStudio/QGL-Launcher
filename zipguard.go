package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	maxZipEntries       = 8192
	maxZipTotalUnpacked = 512 << 20
	maxZipRatio         = 200
	maxZipEntryUnpacked = 256 << 20
	maxZipNameLen       = 512
)

func zipNameInvalid(name string) bool {
	if name == "" || len(name) > maxZipNameLen {
		return true
	}
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return true
	}
	if strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
		return true
	}
	if len(name) >= 2 && name[0] == '.' && name[1] == '.' {
		return true
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func openArchiveBounded(path string) (*zip.ReadCloser, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	if len(r.File) == 0 || len(r.File) > maxZipEntries {
		r.Close()
		return nil, fmt.Errorf("压缩包条目数越界: %d", len(r.File))
	}
	var total uint64
	seen := make(map[string]struct{}, len(r.File))
	for _, f := range r.File {
		if zipNameInvalid(f.Name) {
			r.Close()
			return nil, fmt.Errorf("压缩包条目路径非法: %q", f.Name)
		}
		if _, dup := seen[f.Name]; dup {
			r.Close()
			return nil, fmt.Errorf("压缩包包含重名条目: %q", f.Name)
		}
		seen[f.Name] = struct{}{}
		if f.UncompressedSize64 > maxZipEntryUnpacked {
			r.Close()
			return nil, fmt.Errorf("压缩包单条目解压后过大: %q", f.Name)
		}
		if f.CompressedSize64 > 0 && f.UncompressedSize64/f.CompressedSize64 > maxZipRatio {
			r.Close()
			return nil, fmt.Errorf("压缩包条目压缩比异常: %q", f.Name)
		}
		total += f.UncompressedSize64
		if total > maxZipTotalUnpacked {
			r.Close()
			return nil, fmt.Errorf("压缩包解压总量越界: %d", total)
		}
	}
	return r, nil
}

func readZipEntry(f *zip.File, limit int64) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("压缩包条目为空")
	}
	if int64(f.UncompressedSize64) > limit {
		return nil, fmt.Errorf("压缩包条目超过读取上限: %q", f.Name)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	buf := make([]byte, 0, f.UncompressedSize64)
	chunk := make([]byte, 4096)
	for {
		n, readErr := rc.Read(chunk)
		if n > 0 {
			if int64(len(buf))+int64(n) > limit {
				return nil, fmt.Errorf("压缩包条目实际大小超过上限: %q", f.Name)
			}
			buf = append(buf, chunk[:n]...)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, readErr
		}
		if n == 0 {
			break
		}
	}
	return buf, nil
}
