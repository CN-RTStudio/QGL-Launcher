package main

import (
	"io"
	"os"
)

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
