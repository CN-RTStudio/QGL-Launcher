package main

import (
	"io"
	"os"
	"path/filepath"
)

func (l *boundedLogger) appendBoundedLine(line string) error {
	if len(line) == 0 || line[len(line)-1] != '\n' {
		line += "\n"
	}
	return l.appendBounded(line)
}

func tailBoundedLog(path string, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		return "", nil
	}
	if err := rejectNonRegular(path); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	start := int64(0)
	if info.Size() > maxBytes {
		start = info.Size() - maxBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// boundedLogDir 返回日志文件所在目录（便捷封装，供调用方收权）。
func boundedLogDir(path string) string {
	return filepath.Dir(path)
}
