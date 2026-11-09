package main

// newBoundedLineSplitter 以单行字节上限构造切分器；maxLine<=0 取默认上限。
func newBoundedLineSplitter(maxLine int) *boundedLineSplitter {
	if maxLine <= 0 {
		maxLine = maxGameLogLineBytes
	}
	return &boundedLineSplitter{maxLine: maxLine}
}

// Lines 返回至今切出的逻辑行总数（含被截断的行）。
func (s *boundedLineSplitter) Lines() int64 { return s.lines }

// TruncatedLines 返回至今因超过单行上限而被截断的行数。
func (s *boundedLineSplitter) TruncatedLines() int64 { return s.truncated }

// clippedPrefix 在保证“前缀+截断标记”总长不超过 maxLine 的前提下取前缀。
func (s *boundedLineSplitter) clippedPrefix(data []byte) string {
	keep := s.maxLine - len(gameLogTruncateMarker)
	if keep < 0 {
		keep = 0
	}
	if keep > len(data) {
		keep = len(data)
	}
	return string(data[:keep]) + gameLogTruncateMarker
}

// finishLineAtNewline 处理一个恰好在本块遇到换行的段（seg 不含 '\n'）。
// 丢弃态遇到换行只负责复位；正常态把 buf+seg 合成一行，超长则就地截断
// （该行已结束，不需要进入丢弃态）。
func (s *boundedLineSplitter) finishLineAtNewline(seg []byte) (string, bool) {
	if s.overflow {
		s.overflow = false
		return "", false
	}
	combined := seg
	if len(s.buf) > 0 {
		combined = append(s.buf, seg...)
		s.buf = s.buf[:0]
	}
	if len(combined) > 0 && combined[len(combined)-1] == '\r' {
		combined = combined[:len(combined)-1]
	}
	s.lines++
	if len(combined) <= s.maxLine {
		return string(combined), true
	}
	s.truncated++
	return s.clippedPrefix(combined), true
}
