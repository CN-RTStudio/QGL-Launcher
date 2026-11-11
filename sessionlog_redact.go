package main

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func sanitizeSessionLogLine(raw string, maxBytes int) string {
	runes := []rune(raw)
	var sb strings.Builder
	sb.Grow(len(raw))
	pendingSpace := false
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == 0x1b && i+1 < len(runes) && runes[i+1] == '[' {
			// 跳过 CSI 序列直到终结字节（0x40-0x7E）。
			i += 2
			for i < len(runes) {
				c := runes[i]
				if c >= 0x40 && c <= 0x7e {
					break
				}
				i++
			}
			continue
		}
		if r < 0x20 || r == 0x7f {
			pendingSpace = true
			continue
		}
		if pendingSpace {
			if sb.Len() > 0 {
				sb.WriteByte(' ')
			}
			pendingSpace = false
		}
		sb.WriteRune(r)
	}
	joined := strings.TrimSpace(sb.String())
	// 疑似令牌模式：JWT（含 . 分隔且带 eyJ 头）或 key=value 的值很长。
	joined = redactLikelyToken(joined)
	runes = []rune(joined)
	if len(runes) > maxBytes {
		runes = runes[:maxBytes]
	}
	return string(runes)
}

func redactLikelyToken(s string) string {
	// JWT：header.payload.signature。header 恒为 eyJ 开头，任一位置出现
	// 且带两个点分隔即整体替换（防半截 token 落盘）。
	if strings.Count(s, ".") >= 2 && strings.Contains(s, "eyJ") {
		return "[REDACTED-JWT]"
	}
	// 显式键值令牌：token= / key= / secret= / password= 后面的长串。
	idx := strings.Index(s, "=")
	if idx > 0 && idx < len(s)-16 {
		key := strings.ToLower(strings.TrimSpace(s[:idx]))
		switch {
		case strings.Contains(key, "token"),
			strings.Contains(key, "secret"),
			strings.Contains(key, "password"),
			strings.Contains(key, "apikey"),
			strings.Contains(key, "auth"):
			rest := s[idx+1:]
			if len(rest) >= 16 {
				return s[:idx+1] + "[REDACTED]"
			}
		}
	}
	return s
}

// sessionLogFileNameFor 生成稳定的会话日志文件名：sessionlog-<version>-<stamp>.json。
// version 必须已通过 sanitizePathComponent（调用方负责），stamp 取
// 20060102T150405 形式，保证同一目录下唯一且可按字典序排序（时间序）。
func sessionLogFileNameFor(versionID string, startedAt time.Time) string {
	stamp := startedAt.Format("20060102T150405")
	return "sessionlog-" + versionID + "-" + stamp + ".json"
}

// sessionLogFilePathFor 返回会话日志完整路径（QGL 目录下）。
func sessionLogFilePathFor(qglDir, versionID string, startedAt time.Time) string {
	return filepath.Join(qglDir, sessionLogFileNameFor(versionID, startedAt))
}

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
