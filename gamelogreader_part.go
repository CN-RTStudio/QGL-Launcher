package main

// absorbTrailing 处理“本块剩余部分不再含换行”的数据，返回可能立即产出的
// 截断行（仅在当前未结束行确认超过上限那一刻产出一次）。
func (s *boundedLineSplitter) absorbTrailing(part []byte) string {
	if s.overflow {
		return ""
	}
	room := s.maxLine - len(s.buf)
	if room >= len(part) {
		// 全部放得下（含恰好放满）：暂存，等后续换行再判定。
		s.buf = append(s.buf, part...)
		return ""
	}
	// 合并后严格超过上限：立刻产出截断前缀，后续字节丢弃直到该行换行。
	if room > 0 {
		s.buf = append(s.buf, part[:room]...)
	}
	prefix := s.clippedPrefix(s.buf)
	s.buf = s.buf[:0]
	s.overflow = true
	s.lines++
	s.truncated++
	return prefix
}

// Feed 送入一个读取块，返回这块数据内已经收尾 / 提前截断的逻辑行（不含换行）。
// 分块边界任意：可以从一行中间切开，也可以从 CR 与 LF 之间切开。
func (s *boundedLineSplitter) Feed(chunk []byte) []string {
	if len(chunk) == 0 {
		return nil
	}
	var produced []string
	for len(chunk) > 0 {
		i := indexByte(chunk, '\n')
		if i < 0 {
			if line := s.absorbTrailing(chunk); line != "" {
				produced = append(produced, line)
			}
			break
		}
		if line, ok := s.finishLineAtNewline(chunk[:i]); ok {
			produced = append(produced, line)
		}
		chunk = chunk[i+1:]
	}
	return produced
}

// Flush 在流结束时取出最后一个没有换行结尾的行；无残余返回 nil。
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
