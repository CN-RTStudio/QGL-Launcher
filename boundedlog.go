package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	// boundedLogMaxBytes 单个活动日志文件的软上限（4MiB）。
	boundedLogMaxBytes int64 = 4 << 20
	// boundedLogKeepFiles 除活动文件外保留的归档份数（只有一份 .1）。
	boundedLogKeepFiles = 1
	// boundedLogMaxLineBytes 单条日志在截断前允许的最大字节数（16KiB）。
	boundedLogMaxLineBytes = 16 << 10
	// boundedLogFilePerm 新建日志文件权限：仅属主可读写。
	boundedLogFilePerm os.FileMode = 0o600
)

var errBoundedLogRejected = errors.New("boundedlog: 目标是符号链接或非普通文件，已拒绝")

type boundedLogger struct {
	path     string
	maxBytes int64
	mu       sync.Mutex
}

var boundedLogRegistry sync.Map // path -> *boundedLogger

func getBoundedLogger(path string) *boundedLogger {
	if v, ok := boundedLogRegistry.Load(path); ok {
		return v.(*boundedLogger)
	}
	v, _ := boundedLogRegistry.LoadOrStore(path, &boundedLogger{path: path, maxBytes: boundedLogMaxBytes})
	return v.(*boundedLogger)
}
func clampLogLine(line string) string {
	if len(line) <= boundedLogMaxLineBytes {
		return line
	}
	return line[:boundedLogMaxLineBytes] + "...[truncated]\n"
}
func rejectNonRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 不存在，稍后以普通文件新建即可
		}
		return err
	}
	if !info.Mode().IsRegular() {
		return errBoundedLogRejected
	}
	return nil
}

func (l *boundedLogger) appendBounded(line string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	payload := clampLogLine(line)
	if payload == "" {
		return nil
	}

	if err := rejectNonRegular(l.path); err != nil {
		return err
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, boundedLogFilePerm)
	if err != nil {
		return err
	}
	size := int64(0)
	if info, statErr := f.Stat(); statErr == nil {
		size = info.Size()
	}
	if size+int64(len(payload)) > l.maxBytes {
		// 先关闭再轮转：Windows 上文件被占用时无法 rename，必须释放句柄。
		_ = f.Close()
		if err := l.rotate(); err != nil {
			return err
		}
		// 轮转后以全新空文件重开写本行。
		f2, openErr := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_TRUNC, boundedLogFilePerm)
		if openErr != nil {
			return openErr
		}
		defer f2.Close()
		if _, err := io.WriteString(f2, payload); err != nil {
			return err
		}
		return f2.Sync()
	}

	defer f.Close()
	if _, err := io.WriteString(f, payload); err != nil {
		return err
	}
	return f.Sync()
}

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
