package main

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func persistSessionLog(path string, buf sessionLogBuffer) error {
	if len(buf.lines) == 0 {
		return nil
	}
	lines := buf.lines
	for {
		err := writePrivateJSONBounded(path, lines, maxSessionLogBytes)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errLocalFileTooLarge) || len(lines) <= 1 {
			return err
		}
		lines = lines[1:]
	}
}

// readSessionLog 有界读一份会话日志文件；脏文件按空处理。
func readSessionLog(path string) []sessionLogLine {
	var lines []sessionLogLine
	if err := readLocalJSONBounded(path, &lines, maxSessionLogBytes, "session-log"); err != nil {
		return nil
	}
	clean := make([]sessionLogLine, 0, len(lines))
	for _, l := range lines {
		l.Text = sanitizeSessionLogLine(l.Text, maxSessionLogLineBytes)
		clean = append(clean, l)
	}
	return clean
}

// sessionLogSummary 是日志文件列表项（前端展示用）。
type sessionLogSummary struct {
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Stamp   string    `json:"stamp"`
	Bytes   int64     `json:"bytes"`
	Lines   int       `json:"lines"`
	ModTime time.Time `json:"modTime"`
}

// listSessionLogSummaries 列 QGL 目录下 sessionlog-*.json，按文件名倒序
// （时间序从新到旧）。limit<=0 返回全部。
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

// rotateSessionLogs 删除最旧的会话日志文件，只保留 maxFiles 份。
// 返回删除的文件数。
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
