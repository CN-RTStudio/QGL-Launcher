package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func listSessionLogSummaries(qglDir string, limit int) []sessionLogSummary {
	entries, err := os.ReadDir(qglDir)
	if err != nil {
		return nil
	}
	var out []sessionLogSummary
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "sessionlog-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		// 文件名切出版本与时间戳：sessionlog-<version>-<stamp>.json
		mid := strings.TrimSuffix(strings.TrimPrefix(name, "sessionlog-"), ".json")
		version := ""
		stamp := ""
		if i := strings.LastIndex(mid, "-"); i >= 0 {
			version = mid[:i]
			stamp = mid[i+1:]
		} else {
			version = mid
		}
		out = append(out, sessionLogSummary{
			Name: name, Version: version, Stamp: stamp,
			Bytes: info.Size(), ModTime: info.ModTime(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func rotateSessionLogs(qglDir string, maxFiles int) int {
	sums := listSessionLogSummaries(qglDir, 0)
	if len(sums) <= maxFiles {
		return 0
	}
	removed := 0
	for i := len(sums) - 1; i >= maxFiles; i-- {
		_ = os.Remove(filepath.Join(qglDir, sums[i].Name))
		removed++
	}
	return removed
}

// sessionLogTail 返回指定日志文件尾部最多 n 行（脱敏后）。
func sessionLogTail(qglDir, name string, n int) []sessionLogLine {
	if !strings.HasPrefix(name, "sessionlog-") || !strings.HasSuffix(name, ".json") {
		return nil
	}
	path := filepath.Join(qglDir, name)
	if !PathWithinRoot(path, qglDir) {
		return nil
	}
	lines := readSessionLog(path)
	if n <= 0 || n > len(lines) {
		n = len(lines)
	}
	if n <= 0 {
		return nil
	}
	return lines[len(lines)-n:]
}
