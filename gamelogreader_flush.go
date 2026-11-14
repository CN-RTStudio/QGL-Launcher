package main

func (s *boundedLineSplitter) Flush() []string {
	if s.overflow {
		// 流在丢弃态结束：截断前缀此前已产出并计数，这里只复位。
		s.overflow = false
		return nil
	}
	if len(s.buf) == 0 {
		return nil
	}
	rest := s.buf
	s.buf = nil
	if len(rest) > 0 && rest[len(rest)-1] == '\r' {
		rest = rest[:len(rest)-1]
	}
	s.lines++
	if len(rest) <= s.maxLine {
		return []string{string(rest)}
	}
	s.truncated++
	return []string{s.clippedPrefix(rest)}
}

// indexByte 查找字节 c 第一次出现的位置，不存在返回 -1。
func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// streamBoundedLines 持续从 r 读取并按行回调 yield，直到 EOF 或读取错误。
// 返回总行数、被截断行数与读取错误；yield 按顺序收到完整行（无换行符）。
