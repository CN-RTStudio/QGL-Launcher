package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"sync"
)

const maxJavaVersionOutput int64 = 1 << 20 // 1 MiB
type limitedWriter struct {
	mu  sync.Mutex
	buf *bytes.Buffer
	max int64
	n   int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.n += int64(len(p))
	remain := w.max + 1 - int64(w.buf.Len())
	if remain > 0 {
		if int64(len(p)) < remain {
			remain = int64(len(p))
		}
		w.buf.Write(p[:remain])
	}
	return len(p), nil
}
func isJavaBinaryName(p string) bool {
	switch strings.ToLower(filepath.Base(p)) {
	case "java.exe", "javaw.exe":
		return true
	}
	return false
}
