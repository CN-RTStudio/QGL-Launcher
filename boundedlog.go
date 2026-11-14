package main

import (
	"errors"
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
