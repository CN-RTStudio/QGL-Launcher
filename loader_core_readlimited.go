package main

import (
	"archive/zip"
	_ "embed"
	"fmt"
	"io"
)

func readLimited(r io.Reader, maxSize int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxSize))
}

const apiJSONMaxBytes = 10 << 20

func readZipEntryLimited(f *zip.File, maxBytes int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(maxBytes) {
		return nil, fmt.Errorf("zip 条目解压后声明体积超过 %d 字节: %s", maxBytes, f.Name)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("zip 条目解压后体积超过 %d 字节: %s", maxBytes, f.Name)
	}
	return data, nil
}

// isSafeFileName 验证版本名/文件名只包含安全字符
// 防止路径遍历攻击（../, /, \ 等），只允许字母、数字、点、下划线、短横线
