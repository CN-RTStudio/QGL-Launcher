package main

import (
	"errors"
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
