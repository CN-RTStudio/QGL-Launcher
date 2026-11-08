package main

// sessionlog.go —— 游戏会话日志的脱敏持久化内核。
//
// 游戏进程的 stdout/stderr 逐行流在内存里只保留最近 50 行，崩溃排查靠
// dumpCrashContext 临时读文件。本模块把「每局会话的日志」做成可回溯的
// 私有台账：逐行脱敏（控制字符 / 疑似令牌）、环形缓冲限行限字节、会话
// 结束时整体落盘（0600 私有原子写）、按文件数轮转。纯函数层不依赖
// App 与平台 API，可独立单测。

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxSessionLogLines 单次会话在内存环形缓冲中保留的最大行数。
const maxSessionLogLines = 2000

// maxSessionLogBytes 单次会话日志落盘文件的最大字节数（含 JSON 结构开销）。
const maxSessionLogBytes int64 = 1 << 20 // 1 MiB

// maxSessionLogFiles 保留的会话日志文件份数（超出按最旧轮转删除）。
const maxSessionLogFiles = 24

// maxSessionLogLineBytes 单行日志脱敏后的最大长度。
const maxSessionLogLineBytes = 2048

// sessionLogLine 是落盘文件中的一行记录（时间戳 + 脱敏后的文本）。
type sessionLogLine struct {
	TS   string `json:"ts"`   // RFC3339，日志行到达时间
	Text string `json:"text"` // 脱敏后的日志文本
}

// sessionLogBuffer 是一次会话的日志环形缓冲（纯内存，App 进程内权威）。
type sessionLogBuffer struct {
	lines []sessionLogLine
	bytes int64 // 已占用字节估算（text+ts 之和）
}

// newSessionLogBuffer 返回空缓冲。
func newSessionLogBuffer() sessionLogBuffer {
	return sessionLogBuffer{}
}

// appendSessionLogLine 向环形缓冲追加一行（脱敏 + 限长 + 总量上限）。
// 返回追加是否成功（总量超限时静默丢弃后续行，防内存膨胀）。
func appendSessionLogLine(buf sessionLogBuffer, ts time.Time, raw string) (sessionLogBuffer, bool) {
	text := sanitizeSessionLogLine(raw, maxSessionLogLineBytes)
	if text == "" {
		return buf, true
	}
	rec := sessionLogLine{TS: ts.Format(time.RFC3339), Text: text}
	est := int64(len(rec.TS) + len(rec.Text) + 4) // +4 近似 JSON 引号/冒号
	if buf.bytes+est > maxSessionLogBytes {
		return buf, false
	}
	buf.lines = append(buf.lines, rec)
	buf.bytes += est
	if len(buf.lines) > maxSessionLogLines {
		dropped := buf.lines[0]
		buf.bytes -= int64(len(dropped.TS) + len(dropped.Text) + 4)
		buf.lines = buf.lines[1:]
	}
	return buf, true
}

// sanitizeSessionLogLine 逐字符脱敏一行日志：
//  1. 去掉全部控制字符（游戏崩溃堆栈可能带转义序列/终端控制码），并把
//     ESC [ … 的 CSI 可视控制序列整段跳过（不能只去 ESC 留下 "[31m"）；
//  2. 把疑似令牌的长串（JWT / access_token= 等）替换为占位符，
//     防止日志文件成为二次泄露源；
//  3. 连续控制符压缩为一个空格，尾部空白裁剪；
//  4. 按 maxBytes 截断。
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

// redactLikelyToken 将 JWT / Bearer / 形如 xxx=eyJ... 的疑似令牌替换为占位。
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

// persistSessionLog 把缓冲整体落盘（私有原子写）。空日志不落盘。
// writePrivateJSONBounded 自带序列化与超限拒绝；超限时从最旧行起裁，
// 直到能装下或只剩一行（只剩一行仍超限则如实报错，不吞错误）。
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
