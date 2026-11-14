package main

func newBoundedLineSplitter(maxLine int) *boundedLineSplitter {
	if maxLine <= 0 {
		maxLine = maxGameLogLineBytes
	}
	return &boundedLineSplitter{maxLine: maxLine}
}
func (s *boundedLineSplitter) Lines() int64          { return s.lines }
func (s *boundedLineSplitter) TruncatedLines() int64 { return s.truncated }
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
