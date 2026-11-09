package main

import (
	"strings"
	"time"
)

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
