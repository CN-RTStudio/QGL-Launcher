package main

//
//
//

import (
	"io"
	"os"
	"path/filepath"
)

func (l *boundedLogger) rotate() error {
	backup := l.path + ".1"
	if info, err := os.Lstat(backup); err == nil {
		if !info.Mode().IsRegular() {
			// Remove 删除的是目录项本身；对符号链接只删链接、不动其目标。
			if rmErr := os.Remove(backup); rmErr != nil {
				return rmErr
			}
		}
	}
	// os.Rename 在 Windows 上经 MoveFileEx(REPLACE_EXISTING) 可覆盖已存在的普通 .1。
	return os.Rename(l.path, backup)
}

// appendBoundedLine 是给调用方的便捷入口：自动补末尾换行。
func (l *boundedLogger) appendBoundedLine(line string) error {
	if len(line) == 0 || line[len(line)-1] != '\n' {
		line += "\n"
	}
	return l.appendBounded(line)
}

// tailBoundedLog 读取日志文件至多 maxBytes 的尾部内容，供界面“查看最近日志”使用。
// 归档文件不读取；路径必须是普通文件，符号链接等一律拒绝。文件不存在返回空串。
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
