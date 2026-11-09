package main

//
//
//

import (
	"errors"
	"io"
	"os"
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

// errBoundedLogRejected 表示目标路径不是可安全写入的普通文件。
var errBoundedLogRejected = errors.New("boundedlog: 目标是符号链接或非普通文件，已拒绝")

// boundedLogger 绑定一个日志路径，所有写入经 mu 串行。
type boundedLogger struct {
	path     string
	maxBytes int64
	mu       sync.Mutex
}

// boundedLogRegistry 保证同一物理路径始终拿到同一把锁（writeLog 每次都调用）。
var boundedLogRegistry sync.Map // path -> *boundedLogger

// getBoundedLogger 返回该路径共享的有界日志器；路径不同则各自独立限界。
func getBoundedLogger(path string) *boundedLogger {
	if v, ok := boundedLogRegistry.Load(path); ok {
		return v.(*boundedLogger)
	}
	v, _ := boundedLogRegistry.LoadOrStore(path, &boundedLogger{path: path, maxBytes: boundedLogMaxBytes})
	return v.(*boundedLogger)
}

// clampLogLine 把单条日志限制在 boundedLogMaxLineBytes 内；被截断时追加显式标记，
// 便于事后知道这一行不是完整输出（而不是静默丢字节）。
func clampLogLine(line string) string {
	if len(line) <= boundedLogMaxLineBytes {
		return line
	}
	return line[:boundedLogMaxLineBytes] + "...[truncated]\n"
}

// rejectNonRegular 对路径做 Lstat：存在即必须是普通文件，否则拒绝。
// 用 Lstat 而非 Stat，确保符号链接本身被识别（Stat 会跟随到目标）。
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

// appendBounded 追加一行（需保证以 '\n' 结尾由调用方决定，这里原样写入）。
// 若写入后会越过 maxBytes，则先轮转再写，活动文件因此始终从一个较小的起点重新增长。
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

// rotate 把活动文件改名为 path+".1"（覆盖上一份归档），让活动路径腾空。
// 归档目标若被预置成符号链接 / 特殊文件，先移除该链接本身，绝不覆盖其指向的文件。
